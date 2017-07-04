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

import copy
import ijson

from six import string_types

import utils
import verify

class DEPParseException(verify.DEPException):
    def __init__(self, msg):
        super(DEPParseException, self).__init__(msg)
        self._initargs = (msg,)

class MalformedCertificateException(DEPParseException):
    """
    Indicates that a certificate in the DEP is not properly formed.
    """

    def __init__(self, cert):
        super(MalformedCertificateException, self).__init__(
                _("Malformed certificate: \"{}\"").format(cert))
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
                raise DEPParseException(_('Duplicate DEP root.'))

            self.root_seen = True
            return DEPStateRootMap(self.chunksize, self)

        raise DEPParseException(_('Malformed DEP root.'))

class DEPStateRootMap(DEPStateWithData):
    def __init__(self, chunksize, upper):
        super(DEPStateRootMap, self).__init__(chunksize, upper)
        self.groups_seen = False

    def parse(self, prefix, event, value):
        if prefix == '' and event == 'end_map':
            return self.upper

        if prefix == 'Belege-Gruppe':
            if event != 'start_array':
                raise DEPParseException(_('Malformed DEP root.'))
            if self.groups_seen:
                raise DEPParseException(_('Duplicate DEP root.'))
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

        raise DEPParseException(_('Malformed DEP element: \"Belege-Gruppe\".'))

class DEPStateGroup(DEPStateWithIncompleteData):
    def __init__(self, chunksize, upper, idx):
        super(DEPStateGroup, self).__init__(chunksize, upper, idx)
        self.recs_seen = False
        self.cert_seen = False
        self.cert_list_seen = False

    def parse(self, prefix, event, value):
        if prefix == 'Belege-Gruppe.item' and event == 'end_map':
            if not self.cert_seen:
                raise DEPParseException(
                        _('Malformed DEP element: Certificate in Group {} is missing.').format(self.idx))
            if not self.cert_list_seen:
                raise DEPParseException(
                        _('Malformed DEP element: Certificate chain in Group {} is missing.').format(self.idx))
            if not self.recs_seen:
                raise DEPParseException(
                        _('Malformed DEP element: Receipts in Group {} are missing.').format(self.idx))
            self.mergeIntoChunk()
            return self.upper

        if prefix == 'Belege-Gruppe.item.Signaturzertifikat':
            if event != 'string':
                raise DEPParseException(
                        _('Malformed DEP element: Certificate in Group {} is not a string.').format(self.idx))
            if self.cert_seen:
                raise DEPParseException(
                        _('Malformed DEP element: Duplicate certificate element in Group {}.').format(self.idx))
            self.cert_seen = True
            self.wip.cert = parseDEPCert(value) if value != '' else None

        elif prefix == 'Belege-Gruppe.item.Zertifizierungsstellen':
            if event != 'start_array':
                raise DEPParseException(
                        _('Malformed DEP element: Certificate chain in Group {} is not a list.').format(self.idx))
            if self.cert_list_seen:
                raise DEPParseException(
                        _('Malformed DEP element: Duplicate certificate chain element in Group {}.').format(self.idx))
            self.cert_list_seen = True
            return DEPStateCertList(self.chunksize, self, self.idx)

        elif prefix == 'Belege-Gruppe.item.Belege-kompakt':
            if event != 'start_array':
                raise DEPParseException(
                        _('Malformed DEP element: Receipts in Group {} is not a list.').format(self.idx))
            if self.recs_seen:
                raise DEPParseException(
                        _('Malformed DEP element: Duplicate receipts element in Group {}.').format(self.idx))
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

        raise DEPParseException(
                _('Malformed DEP element in Group {}: \"Zertifizierungsstellen\".').format(self.idx))

class DEPStateReceiptList(DEPStateWithIncompleteData):
    def parse(self, prefix, event, value):
        if prefix == 'Belege-Gruppe.item.Belege-kompakt' and event == 'end_array':
            return self.upper

        if prefix == 'Belege-Gruppe.item.Belege-kompakt.item' \
                and event == 'string':
            self.wip.recs.append(value.encode('utf-8'))
            return self

        raise DEPParseException(
                _('Malformed DEP element in Group {}: \"Belege-kompakt\".').format(self.idx))

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

def getItems(fd, chunksize, prefix, cache):
    if prefix in cache:
        return cache[prefix]

    # cache miss, gotta parse the JSON again
    ofs = fd.tell()
    fd.seek(0)
    items = list(ijson.items(fd, prefix))
    fd.seek(ofs)

    if chunksize == 0 or len(items) <= chunksize:
        cache[prefix] = items

    return items

# TODO: handle empty DEPs
def parseDEP(fd, chunksize = 0):
    parser = ijson.parse(fd)
    state = DEPStateRoot(chunksize)
    cache = dict()

    try:
        for prefix, event, value in parser:
            #print('{}, {}, {}'.format(prefix, event, value))
            nextState = state.parse(prefix, event, value)

            if state.ready():
                needed = state.needCrt()
                if needed is not None:
                    cert_str = getItems(fd, chunksize,
                            'Belege-Gruppe.item.Signaturzertifikat',
                            cache)[needed]
                    cert_str_list = getItems(fd, chunksize,
                            'Belege-Gruppe.item.Zertifizierungsstellen',
                            cache)[needed]
                    cert = parseDEPCert(cert_str) if cert_str != '' else None
                    cert_list = [ parseDEPCert(cs) for cs in cert_str_list ]
                    state.setCrt(cert, cert_list)

                yield state.getChunk()

            state = nextState

        # The entire DEP is parsed, get the rest.
        # We should have found any certs here, so no check needed.
        last = state.getChunk()
        if len(last) > 0:
            yield last
    except ijson.JSONError as e:
        raise DEPParseException(_('Malformed JSON.'))

if __name__ == "__main__":
    import gettext
    gettext.install('rktool', './lang', True)

    from types import MethodType

    import sys
    import key_store
    import verification_state
    import verify_receipt

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

    with open(sys.argv[1]) as f:
        jsonStore = utils.readJsonStream(f)
        key = utils.loadKeyFromJson(jsonStore)
        ks = key_store.KeyStore.readStoreFromJson(jsonStore)

    with open(sys.argv[2]) as f:
        vstate = verification_state.ClusterState()
        prevStart, rState, usedRecIds = vstate.getCashRegisterInfo(0)
        res = None
        for chunks in batchParse(parseDEP(f, int(sys.argv[4])), nprocs):
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
