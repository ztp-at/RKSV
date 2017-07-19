###########################################################################
# Copyright 2017 ZT Prentner IT GmbH
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

from builtins import int
from builtins import range

import copy
import ijson

from math import ceil
from six import string_types

import os
def depParserChunkSize():
    return os.environ.get('RKSV_DEP_CHUNKSIZE', 100000)

import utils
import verify

class DEPParseException(verify.DEPException):
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
            self.cert_chain = list()
            self.recs = list()

    def __init__(self, chunksize, upper, idx):
        super(DEPStateWithIncompleteData, self).__init__(chunksize, upper)
        if hasattr(upper, 'wip'):
            self.wip = upper.wip
        else:
            self.wip = DEPStateWithIncompleteData.WIPData()
        self.idx = idx

    def needCrt(self):
        if self.wip.cert is None or len(self.wip.cert_chain) == 0:
            return self.idx
        return None

    def setCrt(self, cert, cert_chain):
        self.wip.cert = cert
        self.wip.cert_chain = cert_chain

    def mergeIntoChunk(self):
        if len(self.wip.recs) > 0:
            self.chunk.append((self.wip.recs, self.wip.cert, self.wip.cert_chain))
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
                raise MalformedDEPException(_('Duplicate DEP root.'))

            self.root_seen = True
            return DEPStateRootMap(self.chunksize, self)

        raise MalformedDEPException(_('Malformed DEP root.'))

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
                raise MalformedDEPException(_('Malformed DEP root.'))
            if self.groups_seen:
                raise MalformedDEPException(_('Duplicate DEP root.'))
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
                        'not a string', self.idx)
            self.cert_seen = True
            self.wip.cert = parseDEPCert(value) if value != '' else None

        elif prefix == 'Belege-Gruppe.item.Zertifizierungsstellen':
            if self.cert_list_seen:
                raise DuplicateDEPElementException('Zertifizierungsstellen', self.idx)
            if event != 'start_array':
                raise MalformedDEPElementException('Zertifizierungsstellen',
                        'not a list', self.idx)
            self.cert_list_seen = True
            return DEPStateCertList(self.chunksize, self, self.idx)

        elif prefix == 'Belege-Gruppe.item.Belege-kompakt':
            if self.recs_seen:
                raise DuplicateDEPElementException('Belege-kompakt', self.idx)
            if event != 'start_array':
                raise MalformedDEPElementException('Belege-kompakt',
                        'not a list', self.idx)
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
    try:
        return rec.encode('utf-8')
    except TypeError:
        if idx is None:
            raise MalformedDEPElementException('Receipt \"{}\"'.format(rec))
        else:
            raise MalformedDEPElementException('Receipt \"{}\"'.format(rec), idx)

def expandDEPReceipt(rec, idx = None):
    try:
        return rec.decode('utf-8')
    except UnicodeDecodeError:
        if idx is None:
            raise MalformedDEPElementException('Receipt \"{}\"'.format(rec))
        else:
            raise MalformedDEPElementException('Receipt \"{}\"'.format(rec), idx)

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
    def parse(self, chunksize = 0):
        raise NotImplementedError("Please implement this yourself.")

class IncrementalDEPParser(DEPParserI):
    def __init__(self, fd):
        # skipBOM checks if we can seek, so no harm in doing it to a non-file
        self.startpos = utils.skipBOM(fd)
        self.fd = fd

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
    def __init__(self, stream):
        super(StreamDEPParser, self).__init__(stream)

    def _needCerts(self, state, chunksize, groupidx):
        raise MalformedDEPException(
                _("Element \"Signaturzertifikat\" or \"Zertifizierungsstellen\" missing"),
                groupidx)

    def parse(self, chunksize = 0):
        for chunk in super(StreamDEPParser, self).parse(chunksize):
            yield chunk

class CertlessStreamDEPParser(StreamDEPParser):
    def _needCerts(self, state, chunksize, groupidx):
        # Do nothing, we don't really care about certs.
        # The parser will still fail if they are outright missing, but we are ok
        # with returning chunks without certs even though the DEP contains some.
        pass

class FileDEPParser(IncrementalDEPParser):
    def __init__(self, fd):
        super(FileDEPParser, self).__init__(fd)

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
        for chunk in super(FileDEPParser, self).parse(chunksize):
            yield chunk

class DictDEPParser(DEPParserI):
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
        receipts = list(map(shrinkDEPReceipt, group['Belege-kompakt']))

        if not isinstance(cert_str, string_types):
            raise MalformedDEPElementException('Signaturzertifikat',
                    'not a string', self.idx)
        if not isinstance(cert_str_list, list):
            raise MalformedDEPElementException('Zertifizierungsstellen',
                    'not a list', self.idx)
        if not isinstance(receipts, list):
            raise MalformedDEPElementException('Belege-kompakt',
                    'not a list', self.idx)

        cert = parseDEPCert(cert_str) if cert_str != '' else None
        cert_list = [ parseDEPCert(cs) for cs in cert_str_list ]

        return receipts, cert, cert_list

    def _groupChunkGen(self, chunksize, groups):
        if chunksize == 0:
            for groupidx in range(0, len(groups)):
                recs, cert, certs = self._parseDEPGroup(groups[groupidx], groupidx)
                if len(recs) > 0:
                    yield [(recs, cert, certs)]
            return

        chunk = list()
        chunklen = 0
        for groupidx in range(0, len(groups)):
            recs, cert, cert_list = self._parseDEPGroup(groups[groupidx], groupidx)
            while len(recs) > 0:
                recs_needed = chunksize - chunklen
                nextrecs = recs[0:recs_needed]
                chunk.append((nextrecs, cert, cert_list))
                chunklen += len(nextrecs)
                recs = recs[recs_needed:]

                if chunklen >= chunksize:
                    yield chunk
                    chunk = list()
                    chunklen = 0

        if chunklen > 0:
            yield chunk

    def parse(self, chunksize = 0):
        if not isinstance(self.dep, dict):
            raise MalformedDEPException(_('Malformed DEP root.'))
        if 'Belege-Gruppe' not in self.dep:
            raise MissingDEPElementException('Belege-Gruppe')

        bg = self.dep['Belege-Gruppe']
        if not isinstance(bg, list) or len(bg) <= 0:
            raise MalformedDEPElementException('Belege-Gruppe')

        if self.nparts > 1 and not chunksize:
            def _nrecs(group):
                try:
                    return len(group['Belege-kompakt'])
                except (TypeError, KeyError):
                    return 0

            nrecs = sum(_nrecs(g) for g in bg)
            chunksize = int(ceil(float(nrecs) / self.nparts))

        got_something = False
        for chunk in self._groupChunkGen(chunksize, bg):
            yield chunk
            got_something = True

        if not got_something:
            raise MalformedDEPException(_('No receipts found'))

if __name__ == "__main__":
    import gettext
    gettext.install('rktool', './lang', True)

    from types import MethodType

    import sys
    import key_store
    import verification_state
    import verify_receipt
    import json

    def packageChunk(chunk, keyStore):
        groupsWithVerifiers = list()
        if len(chunk) == 1:
            recs, cert, chain = chunk[0]
            if not cert:
                rv = verify_receipt.ReceiptVerifier.fromKeyStore(keyStore)
            else:
                verify.verifyCert(cert, chain, keyStore)
                rv = verify_receipt.ReceiptVerifier.fromCert(cert)

            groupsWithVerifiers.append((recs, rv))
        else:
            for recs, cert, chain in chunk:
                if not cert:
                    raise verify.NoCertificateGivenException()
                verify.verifyCert(cert, chain, keyStore)
                rv = verify_receipt.ReceiptVerifier.fromCert(cert)
                groupsWithVerifiers.append((recs, rv))
        return groupsWithVerifiers

    def batchParse(allChunks, n):
        ret = list()
        for chunk in allChunks:
            ret.append(chunk)
            if len(ret) >= n:
                yield ret
                ret = list()

        if len(ret) > 0:
            yield ret

    if len(sys.argv) != 5:
        sys.exit(7)

    nprocs = int(sys.argv[3])
    pool = None
    if nprocs > 1:
        import multiprocessing
        pool = multiprocessing.Pool(nprocs)
    else:
        nprocs = 1

    with open(sys.argv[1]) as f:
        jsonStore = utils.readJsonStream(f)
        key = utils.loadKeyFromJson(jsonStore)
        ks = key_store.KeyStore.readStoreFromJson(jsonStore)

    with open(sys.argv[2]) as f:
        parser = DictDEPParser(utils.readJsonStream(f), nprocs)
        #parser = FileDEPParser(f)
        vstate = verification_state.ClusterState()
        prevStart, rState, usedRecIds = vstate.getCashRegisterInfo(0)
        res = None
        for chunks in batchParse(parser.parse(int(sys.argv[4])), nprocs):
            pkgs = [ packageChunk(chunk, ks) for chunk in chunks ]
            npkgs = len(pkgs)

            if res is not None:
                outRStates, outUsedRecIds = zip(*res.get())
                usedRecIds = verify.verifyParsedDEP_finalize(outUsedRecIds, usedRecIds)
                rState = outRStates[-1]
                print('batch')

            # create start cashreg state for each package
            pkgRStates = [rState]
            pkgRState = rState
            for pkg in pkgs:
                for group, rv in pkg:
                    pkgRState = verification_state.CashRegisterState.fromDEPGroup(
                            pkgRState, group, key)
                pkgRStates.append(pkgRState)
            del pkgRStates[-1]
            
            wargs = zip(pkgs, [key] * npkgs, [prevStart] * npkgs, pkgRStates,
                    [set()] * npkgs)

            # apply verifyGroup() to each package
            if not pool:
                outresults = map(verify.verifyGroupsWithVerifiersTuple, wargs)
                res = type('DummyAsyncResult', (object,), {"data": outresults})
                res.get = MethodType(lambda self: self.data, res)
            else:
                res = pool.map_async(verify.verifyGroupsWithVerifiersTuple, wargs)

        outRStates, outUsedRecIds = zip(*res.get())
        usedRecIds = verify.verifyParsedDEP_finalize(outUsedRecIds, usedRecIds)
        rState = outRStates[-1]

        vstate.updateCashRegisterInfo(0, rState, usedRecIds)
