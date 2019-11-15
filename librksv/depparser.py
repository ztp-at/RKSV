###########################################################################
# Copyright 2017 ZT Prentner IT GmbH (www.ztp.at)
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
###########################################################################

"""
This module provides functions to parse a DEP.
"""

from builtins import int
from builtins import range

from .gettext_helper import _

import copy
import ijson

from math import ceil
from six import string_types

from . import utils
from . import receipt

class DEPException(utils.RKSVVerifyException):
    """
    An exception that is thrown if something is wrong with a DEP.
    """
    pass

class DEPParseException(DEPException):
    """
    Indicates that an error occurred while parsing the DEP.
    """

    def __init__(self, msg):
        super(DEPParseException, self).__init__(msg)
        self._initargs = (msg,)

class MalformedDEPException(DEPParseException):
    """
    Indicates that the DEP is not properly formed.
    """

    def __init__(self, msg=None, groupidx=None):
        if msg is None:
            super(MalformedDEPException, self).__init__(_("Malformed DEP"))
        else:
            if groupidx is None:
                super(MalformedDEPException, self).__init__(
                        _('{}.').format(msg))
            else:
                super(MalformedDEPException, self).__init__(
                        _("In group {}: {}.").format(groupidx, msg))
        self._initargs = (msg, groupidx)

class MissingDEPElementException(MalformedDEPException):
    """
    Indicates that an element in the DEP is missing.
    """

    def __init__(self, elem, groupidx=None):
        super(MissingDEPElementException, self).__init__(
                _("Element \"{}\" missing").format(elem),
                groupidx)
        self._initargs = (elem, groupidx)

class MalformedDEPElementException(MalformedDEPException):
    """
    Indicates that an element in the DEP is malformed.
    """

    def __init__(self, elem, detail=None, groupidx=None):
        if detail is None:
            super(MalformedDEPElementException, self).__init__(
                    _("Element \"{}\" malformed").format(elem),
                    groupidx)
        else:
            super(MalformedDEPElementException, self).__init__(
                    _("Element \"{}\" malformed: {}").format(elem, detail),
                    groupidx)
        self._initargs = (elem, detail, groupidx)


class DuplicateDEPElementException(MalformedDEPException):
    """
    Indicates that an element in the DEP is redundant.
    """

    def __init__(self, elem, groupidx=None):
        super(DuplicateDEPElementException, self).__init__(
                _("Duplicate element \"{}\"").format(elem),
                groupidx)
        self._initargs = (elem, groupidx)

class MalformedCertificateException(DEPParseException):
    """
    Indicates that a certificate in the DEP is not properly formed.
    """

    def __init__(self, cert):
        super(MalformedCertificateException, self).__init__(
                _("Certificate \"{}\" malformed.").format(cert))
        self._initargs = (cert,)

class DEPState(object):
    def __init__(self, upper = None):
        self.upper = upper

    def parse(self, prefix, event, value):
        raise NotImplementedError("Please implement this yourself.")

    def ready(self):
        return False

    def getChunk(self):
        raise NotImplementedError("Please implement this yourself.")

    def needCrt(self):
        return None

    def setCrt(self, cert, cert_chain):
        raise NotImplementedError("Please implement this yourself.")

class DEPStateWithData(DEPState):
    def __init__(self, chunksize, upper = None):
        super(DEPStateWithData, self).__init__(upper)
        self.chunksize = chunksize
        if upper:
            self.chunk = self.upper.chunk
        else:
            self.chunk = list()

    def currentChunksize(self):
        return sum(len(recs) for recs, cert, cert_chain in self.chunk)

    def ready(self):
        if self.chunksize == 0:
            return False

        return self.currentChunksize() >= self.chunksize

    def getChunk(self):
        if self.currentChunksize() <= 0:
            return []

        # Note that we only copy the groups (of which there are hopefully few)
        # FIXME: but still...
        ret = copy.copy(self.chunk)
        del self.chunk[:]
        return ret

class DEPStateWithIncompleteData(DEPStateWithData):
    class WIPData(object):
        def __init__(self):
            self.cert = None
            self.cert_chain = None
            self.recs = list()

    def __init__(self, chunksize, upper, idx):
        super(DEPStateWithIncompleteData, self).__init__(chunksize, upper)
        if hasattr(upper, 'wip'):
            self.wip = upper.wip
        else:
            self.wip = DEPStateWithIncompleteData.WIPData()
        self.idx = idx

    def needCrt(self):
        if self.wip.cert is None or self.wip.cert_chain is None:
            return self.idx
        return None

    def setCrt(self, cert, cert_chain):
        self.wip.cert = cert
        self.wip.cert_chain = cert_chain

    def mergeIntoChunk(self):
        if len(self.wip.recs) > 0:
            clist = self.wip.cert_chain
            if clist is None:
                clist = list()

            self.chunk.append((self.wip.recs, self.wip.cert, clist))
            self.wip.recs = list()

    def ready(self):
        if self.chunksize == 0:
            return False

        return self.currentChunksize() + len(self.wip.recs) >= self.chunksize

    def getChunk(self):
        self.mergeIntoChunk()
        return super(DEPStateWithIncompleteData, self).getChunk()

class DEPStateRoot(DEPStateWithData):
    def __init__(self, chunksize):
        super(DEPStateRoot, self).__init__(chunksize)
        self.root_seen = False

    def parse(self, prefix, event, value):
        if prefix == '' and event == 'start_map' and value == None:
            if self.root_seen:
                raise MalformedDEPException(_('Duplicate DEP root'))

            self.root_seen = True
            return DEPStateRootMap(self.chunksize, self)

        raise MalformedDEPException(_('Malformed DEP root'))

class DEPStateRootMap(DEPStateWithData):
    def __init__(self, chunksize, upper):
        super(DEPStateRootMap, self).__init__(chunksize, upper)
        self.groups_seen = False

    def parse(self, prefix, event, value):
        if prefix == '' and event == 'end_map':
            if not self.groups_seen:
                raise MissingDEPElementException('Belege-Gruppe')
            return self.upper

        if prefix == 'Belege-Gruppe':
            if event != 'start_array':
                raise MalformedDEPException(_('Malformed DEP root'))
            if self.groups_seen:
                raise MalformedDEPException(_('Duplicate DEP root'))
            self.groups_seen = True
            return DEPStateBGList(self.chunksize, self)

        # TODO: handle other elements
        return self

class DEPStateBGList(DEPStateWithData):
    def __init__(self, chunksize, upper):
        super(DEPStateBGList, self).__init__(chunksize, upper)
        self.curIdx = 0

    def parse(self, prefix, event, value):
        if prefix == 'Belege-Gruppe' and event == 'end_array':
            return self.upper

        if prefix == 'Belege-Gruppe.item' and event == 'start_map':
            nextState = DEPStateGroup(self.chunksize, self, self.curIdx)
            self.curIdx += 1
            return nextState

        raise MalformedDEPElementException('Belege-Gruppe')

class DEPStateGroup(DEPStateWithIncompleteData):
    def __init__(self, chunksize, upper, idx):
        super(DEPStateGroup, self).__init__(chunksize, upper, idx)
        self.recs_seen = False
        self.cert_seen = False
        self.cert_list_seen = False

    def parse(self, prefix, event, value):
        if prefix == 'Belege-Gruppe.item' and event == 'end_map':
            if not self.cert_seen:
                raise MissingDEPElementException('Signaturzertifikat', self.idx)
            if not self.cert_list_seen:
                raise MissingDEPElementException('Zertifizierungsstellen', self.idx)
            if not self.recs_seen:
                raise MissingDEPElementException('Belege-kompakt', self.idx)
            self.mergeIntoChunk()
            return self.upper

        if prefix == 'Belege-Gruppe.item.Signaturzertifikat':
            if self.cert_seen:
                raise DuplicateDEPElementException('Signaturzertifikat', self.idx)
            if event != 'string':
                raise MalformedDEPElementException('Signaturzertifikat',
                        _('not a string'), self.idx)
            self.cert_seen = True
            self.wip.cert = parseDEPCert(value) if value != '' else None

        elif prefix == 'Belege-Gruppe.item.Zertifizierungsstellen':
            if self.cert_list_seen:
                raise DuplicateDEPElementException('Zertifizierungsstellen', self.idx)
            if event != 'start_array':
                raise MalformedDEPElementException('Zertifizierungsstellen',
                        _('not a list'), self.idx)
            self.wip.cert_chain = list()
            self.cert_list_seen = True
            return DEPStateCertList(self.chunksize, self, self.idx)

        elif prefix == 'Belege-Gruppe.item.Belege-kompakt':
            if self.recs_seen:
                raise DuplicateDEPElementException('Belege-kompakt', self.idx)
            if event != 'start_array':
                raise MalformedDEPElementException('Belege-kompakt',
                        _('not a list'), self.idx)
            self.recs_seen = True
            return DEPStateReceiptList(self.chunksize, self, self.idx)

        # TODO: handle other elements
        return self

class DEPStateCertList(DEPStateWithIncompleteData):
    def parse(self, prefix, event, value):
        if prefix == 'Belege-Gruppe.item.Zertifizierungsstellen' and event == 'end_array':
            return self.upper

        if prefix == 'Belege-Gruppe.item.Zertifizierungsstellen.item' \
                and event == 'string':
            self.wip.cert_chain.append(parseDEPCert(value))
            return self

        raise MalformedDEPElementException('Zertifizierungsstellen', self.idx)

class DEPStateReceiptList(DEPStateWithIncompleteData):
    def parse(self, prefix, event, value):
        if prefix == 'Belege-Gruppe.item.Belege-kompakt' and event == 'end_array':
            return self.upper

        if prefix == 'Belege-Gruppe.item.Belege-kompakt.item' \
                and event == 'string':
            self.wip.recs.append(shrinkDEPReceipt(value))
            return self

        raise MalformedDEPElementException('Belege-kompakt', self.idx)

def shrinkDEPReceipt(rec, idx = None):
    """
    Encode a JWS receipt string to a bytes representation. This takes up less
    memory.
    :param rec: The receipt JWS as a string.
    :param idx: The index of the group in the DEP to which the receipt belongs
    or None if it is unknown. This is only used to generate error messages.
    :return: The receipt JWS as a byte array.
    """
    try:
        return rec.encode('utf-8')
    except TypeError:
        if idx is None:
            raise MalformedDEPElementException(_('Receipt \"{}\"').format(rec))
        else:
            raise MalformedDEPElementException(_('Receipt \"{}\"').format(rec), idx)

def expandDEPReceipt(rec, idx = None):
    """
    Decodes a receipt JWS byte array to a regular string.
    :param rec: The receipt JWS as a byte array.
    :param idx: The index of the group in the DEP to which the receipt belongs
    or None if it is unknown. This is only used to generate error messages.
    :return: The receipt JWS as a string.
    """
    try:
        return rec.decode('utf-8')
    except UnicodeDecodeError:
        if idx is None:
            raise MalformedDEPElementException(_('Receipt \"{}\"').format(rec))
        else:
            raise MalformedDEPElementException(_('Receipt \"{}\"').format(rec), idx)

def parseDEPCert(cert_str):
    """
    Turns a certificate string as used in a DEP into a certificate object.
    :param cert_str: A certificate in PEM format without header and footer
    and on a single line.
    :return: A cryptography certificate object.
    :throws: MalformedCertificateException
    """
    if not isinstance(cert_str, string_types):
        raise MalformedCertificateException(cert_str)

    try:
        return utils.loadCert(utils.addPEMCertHeaders(cert_str))
    except ValueError:
        raise MalformedCertificateException(cert_str)

class DEPParserI(object):
    """
    The base class for DEP parsers. This interface allows reading a DEP in
    small chunks without having to store it in memory entirely. Do not use this
    directly, use one of the subclasses.
    """

    def parse(self, chunksize = 0):
        """
        This function parses a DEP and yields chunks of at most chunksize
        receipts. A chunk is a list of group tuples. Every group tuple consists
        of a list of receipt JWS as byte arrays, a certificate object
        containing the certificate used to sign the receipts (or None) and a
        list of certificate objects with the certificates used to sign the
        first certificate (or an empty list) in that order.
        If the chunksize is non-zero, every chunk is guaranteed to contain at
        most chunksize receipts in total (over all groups). Otherwise, the
        maximum number of receipts is implementation dependent. Every yielded
        chunk is guaranteed to contain at least one group tuple.
        :param chunksize: A positive number specifying the maximum number of
        receipts in one chunk or zero.
        :yield: One chunk at a time as described above.
        :throws: DEPParseException
        """
        raise NotImplementedError("Please implement this yourself.")

class IncrementalDEPParser(DEPParserI):
    """
    A DEP parser that reads a DEP from a file descriptor. Do not use this
    directly, use one of the subclasses or the fromFd() method which will return
    an appropriate parser object.
    """

    def __init__(self, fd):
        # skipBOM checks if we can seek, so no harm in doing it to a non-file
        self.startpos = utils.skipBOM(fd)
        self.fd = fd

    @staticmethod
    def fromFd(fd, need_certs=True):
        """
        Returns a new IncrementalDEPParser object using the specified file
        descriptor. If chunks don't necessarily have to contain the DEP group
        certificates (because, for example, no signature verification is
        performed), the need_certs parameter can be set to False. In this case
        fromFd() will return a CertlessStreamDEPParser. If need_certs is True,
        it will return a FileDEPParser for a seekable file descriptor and a
        StreamDEPParser for a non-seekable one.
        :param fd: The file descriptor to use.
        :param need_certs: Whether chunks need to contain the group
        certificates.
        :return: An IncrementalDEPParser object using fd as data source.
        """
        if not need_certs:
            return CertlessStreamDEPParser(fd)
        try:
            fd.tell()
            return FileDEPParser(fd)
        except IOError:
            return StreamDEPParser(fd)

    def _needCerts(self, state, chunksize, groupidx):
        raise NotImplementedError("Please implement this yourself.")

    def parse(self, chunksize = 0):
        parser = ijson.parse(self.fd)
        state = DEPStateRoot(chunksize)
        got_something = False

        try:
            for prefix, event, value in parser:
                nextState = state.parse(prefix, event, value)

                if state.ready():
                    needed = state.needCrt()
                    if needed is not None:
                        self._needCerts(state, chunksize, needed)

                    yield state.getChunk()
                    got_something = True

                state = nextState

            # The entire DEP is parsed, get the rest.
            # We should have found any certs here, so no check needed.
            last = state.getChunk()
            if len(last) > 0:
                yield last
            elif not got_something:
                raise MalformedDEPException(_('No receipts found'))
        except ijson.JSONError as e:
            raise DEPParseException(_('Malformed JSON: {}.').format(e))


class StreamDEPParser(IncrementalDEPParser):
    """
    A DEP parser that reads a DEP from a stream type file descriptor. Such a
    file descriptor is not seekable. The parse() method will raise an exception
    if an element needed to construct a chunk was not read by the time the
    chunk has to be yielded. It will not perform any look-ahead operations
    because all receipts read until the missing elements are found would need
    to be stored in memory, thus defeating the purpose of the parser API.
    A chunksize of zero for the parse() method will cause all receipts in the
    DEP to be returned in a single chunk.
    """

    def _needCerts(self, state, chunksize, groupidx):
        raise MalformedDEPException(
                _("Element \"Signaturzertifikat\" or \"Zertifizierungsstellen\" missing"),
                groupidx)

    def parse(self, chunksize = 0):
        return super(StreamDEPParser, self).parse(chunksize)

class CertlessStreamDEPParser(StreamDEPParser):
    """
    This DEP parser behaves identically to StreamDEPParser, except for the
    fact, that it will not raise an exception if a DEP element needed to
    construct the current chunk has not been read yet. Instead, the yielded
    chunk will have these elements set to None (for Signaturzertifikat) and the
    empty list (for Zertifizierungsstellen) respectively.
    Note that the parser will still not tolerate if the elements are missing
    altogether.
    """

    def _needCerts(self, state, chunksize, groupidx):
        # Do nothing, we don't really care about certs.
        # The parser will still fail if they are outright missing, but we are ok
        # with returning chunks without certs even though the DEP contains some.
        pass

class FileDEPParser(IncrementalDEPParser):
    """
    A DEP parser that reads a DEP from a seekable file. If DEP elements needed
    to construct the current chunk are missing, this parser will perform an
    additional parsing pass to locate these elements before returning the
    chunk. If the total number of such elements is less than the given
    chunksize, they will be cached in memory to avoid having to do even more
    parsing passes.
    A chunksize of zero for the parse() method will cause all receipts in the
    DEP to be returned in a single chunk.
    """

    def __getItems(self, prefix, chunksize):
        if prefix in self.cache:
            return self.cache[prefix]

        # cache miss, gotta parse the JSON again
        ofs = self.fd.tell()
        self.fd.seek(self.startpos)
        items = list(ijson.items(self.fd, prefix))
        self.fd.seek(ofs)

        if chunksize == 0 or len(items) <= chunksize:
            self.cache[prefix] = items

        return items

    def _needCerts(self, state, chunksize, groupidx):
        cert_str = self.__getItems(
                'Belege-Gruppe.item.Signaturzertifikat', chunksize)[groupidx]
        cert_str_list = self.__getItems(
                'Belege-Gruppe.item.Zertifizierungsstellen', chunksize)[groupidx]
        cert = parseDEPCert(cert_str) if cert_str != '' else None
        cert_list = [ parseDEPCert(cs) for cs in cert_str_list ]
        state.setCrt(cert, cert_list)

    def parse(self, chunksize = 0):
        self.fd.seek(self.startpos)
        self.cache = dict()
        return super(FileDEPParser, self).parse(chunksize)


def totalRecsInDictDEP(dep):
    def _nrecs(group):
        try:
            recs = group['Belege-kompakt']
            if not isinstance(recs, list):
                return 0
            return len(recs)
        except (TypeError, KeyError):
            return 0

    bg = dep.get('Belege-Gruppe', [])
    if not isinstance(bg, list):
        return 0

    return sum(_nrecs(g) for g in bg)


class DictDEPParser(DEPParserI):
    """
    A DEP parser that accepts an already parsed dictionary data structure and
    yields chunks of the requested size. This parser is intended to parse DEPs
    that are already completely in memory anyway but emulates the parser API
    for compatibility.
    If the chunksize is zero and the nparts parameter equals 1, the parse()
    method will return each group in the DEP in its own chunk.
    If the chunksize is zero and the nparts parameter is greater than 1, the
    parse() method will try to evenly distribute the receipts over nparts
    chunks. It will then yield at most nparts chunks.
    """

    def __init__(self, dep, nparts = 1):
        self.dep = dep
        self.nparts = nparts
        pass

    def _parseDEPGroup(self, group, idx):
        if not isinstance(group, dict):
            raise MalformedDEPElementException('Belege-Gruppe', idx)

        if 'Belege-kompakt' not in group:
            raise MissingDEPElementException('Belege-kompakt', idx)

        if 'Signaturzertifikat' not in group:
            raise MissingDEPElementException('Signaturzertifikat', idx)

        if 'Zertifizierungsstellen' not in group:
            raise MissingDEPElementException('Zertifizierungsstellen', idx)

        cert_str = group['Signaturzertifikat']
        cert_str_list = group['Zertifizierungsstellen']
        receipts = (shrinkDEPReceipt(r) for r in group['Belege-kompakt'])

        if not isinstance(cert_str, string_types):
            raise MalformedDEPElementException('Signaturzertifikat',
                    _('not a string'), idx)
        if not isinstance(cert_str_list, list):
            raise MalformedDEPElementException('Zertifizierungsstellen',
                    _('not a list'), idx)
        try:
            iter(receipts)
        except TypeError:
            raise MalformedDEPElementException('Belege-kompakt',
                    _('not a list'), idx)

        cert = parseDEPCert(cert_str) if cert_str != '' else None
        cert_list = [ parseDEPCert(cs) for cs in cert_str_list ]

        return receipts, cert, cert_list

    def _groupChunkGen(self, chunksize, groups):
        if chunksize == 0:
            groupidx = 0
            for group in groups:
                recgen, cert, certs = self._parseDEPGroup(group, groupidx)
                recs = list(recgen)
                if len(recs) > 0:
                    yield [(recs, cert, certs)]
                groupidx += 1
            return

        chunk = list()
        chunklen = 0
        groupidx = 0
        for group in groups:
            recgen, cert, cert_list = self._parseDEPGroup(group, groupidx)
            nextrecs = list()
            for rec in recgen:
                nextrecs.append(rec)
                chunklen += 1

                if chunklen >= chunksize:
                    chunk.append((nextrecs, cert, cert_list))
                    yield chunk
                    nextrecs = list()
                    chunk = list()
                    chunklen = 0

            if len(nextrecs) > 0:
                chunk.append((nextrecs, cert, cert_list))
            groupidx += 1

        if chunklen > 0:
            yield chunk

    def parse(self, chunksize = 0):
        if not isinstance(self.dep, dict):
            raise MalformedDEPException(_('Malformed DEP root'))
        if 'Belege-Gruppe' not in self.dep:
            raise MissingDEPElementException('Belege-Gruppe')

        bg = self.dep['Belege-Gruppe']
        if not isinstance(bg, list) or not bg:
            raise MalformedDEPElementException('Belege-Gruppe')

        if self.nparts > 1 and not chunksize:
            nrecs = totalRecsInDictDEP(self.dep)
            chunksize = int(ceil(float(nrecs) / self.nparts))

        got_something = False
        for chunk in self._groupChunkGen(chunksize, bg):
            yield chunk
            got_something = True

        if not got_something:
            raise MalformedDEPException(_('No receipts found'))

class FullFileDEPParser(DEPParserI):
    """
    This parser behaves like DictDEPParser but accepts a file descriptor from
    which to read the JSON instead of an already parsed dictionary structure.
    The file is read in its entirety on the first call to parse() and JSON
    parsed contents are kept in memory. Subsequent calls reuse these contents.
    """

    def __init__(self, fd, nparts = 1):
        self.fd = fd
        self.nparts = nparts
        self.dictParser = None

    def parse(self, chunksize = 0):
        if not self.dictParser:
            try:
                dep = utils.readJsonStream(self.fd)
            except (IOError, UnicodeDecodeError, ValueError) as e:
                raise DEPParseException(_('Malformed JSON: {}.').format(e))
            self.dictParser = DictDEPParser(dep, self.nparts)

        return self.dictParser.parse(chunksize)

def receiptGroupAdapter(depgen):
    for chunk in depgen:
        for recs, cert, cert_list in chunk:
            rec_tuples = [ receipt.Receipt.fromJWSString(expandDEPReceipt(r))
                    for r in recs ]
            recs = None
            yield (rec_tuples, cert, cert_list)
            rec_tuples = None
        chunk = None
