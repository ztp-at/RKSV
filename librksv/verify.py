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
This module provides functions to verify a DEP.
"""

from builtins import int
from builtins import range

from .gettext_helper import _

import base64
import copy

from itertools import groupby
from math import ceil
from six import string_types
from types import MethodType

from . import algorithms
from . import depparser
from . import key_store
from . import receipt
from . import utils
from . import verification_state
from . import verify_receipt

# TODO: note that states put out by "continued" verifications may be useless or
#       broken, or never return a state at all... -- done, still return a
#       state, warn somewhere
# TODO: right now duplicate receipt IDs, where the receipt causes an unrelated
#       Exception will not be detected.
# TODO: make it very clear that a resumed verification is not guaranteed to find
#       all errors! If multiple things are wrong on the same receipt then just
#       one will show up!
# TODO: DEPParseException should always be fatal. -- done
# TODO: DEPReceiptException should all result from a check against the previous
#       receipt and should be restartable with the state reconstruction. Use
#       fromArbitraryReceipt and extend it to take the previous state and only
#       override what can be inferred from the current receipt (i.e. keep old
#       turnover counter UNLESS the current receipt contains one). -- done.
# TODO: ReceiptExceptions should all result from the current receipt and should
#       be restartable by skipping the broken receipt and reconstructing the
#       state for the next one. -- done.
# TODO: The remaining DEPExceptions need to be handled on a case by case basis
#       and should either be fatal or logged only once. -- probably only
#       DuplicateReceiptIdException -- done
# TODO: On restarts we need to handle the turnover counter somehow. -- done,
#       reconstruct if possible, keep old one otherwise
# TODO: We need to be able to determine where to restart a group. By either
#       keeping count or removing receipts from the group list at the end of
#       the loop in verifyGroup(). -- done, removing from list
# TODO: We need a container exception of sorts for multiple occurred errors and
#       we need to find a proper type for it. -- done
# TODO: Extend groupWithVerifiersTuple thing with an addtional exception return
#       value or see if map_async let's us get at individual exceptions. -- We
#       can handle individual exceptions BUT we need proper handling of the used
#       receipts log -- done, return non-fatal exceptions as additional value
# TODO: update the cashreg state inplace intelligently, after a receipt has
#       been handled the state should update, if a receipt fails it should
#       remain at the state after the previous receipt. -- done, needs testing
# TODO: prevent/catch (and test for) exceptions in the state
#       estimation/reconstruction (which can cause infinite loops or break the
#       chunking before we even start the actual group verification) -- for now
#       just catch around prepareVerificationTuples and merge with previous
#       errors, later maybe construct a new state if estimation fails
#       (generalize fromArbitraryReceipt) -- done, changed state estimation to
#       keep going as long as possible, reconstruct state from the first receipt
#       in the next group if estimation fails and continue, should fail again in
#       the actual verification

class ClusterInOpenSystemException(depparser.DEPException):
    """
    This exception indicates that a cluster of cash registers was
    detected in an open system.
    """

    def __init__(self):
        super(ClusterInOpenSystemException, self).__init__(
                _("GGS Cluster is not supported in an open system."))
        self._initargs = ()

class DEPReceiptException(depparser.DEPException):
    """
    This exception indicates that an error was found in a DEP at a
    specific receipt.
    """

    def __init__(self, receipt, message):
        super(DEPReceiptException, self).__init__(
                _("At receipt \"{0}\": {1}").format(receipt, message))
        self.receipt = receipt
        self._initargs = (receipt, message)

class ChainingException(DEPReceiptException):
    """
    This exception indicates that the chaining value in a receipt is invalid and
    that the chain of receipts can not be verified.
    """

    def __init__(self, rec, recPrev = 'THIS IS A BUG'):
        super(ChainingException, self).__init__(rec,
                _("Chaining value \"{0}\" invalid.").format(recPrev))
        self._initargs = (rec, recPrev)

class NoRestoreReceiptAfterSignatureSystemFailureException(DEPReceiptException):
    """
    This exception indicates that, after a signature system is first used or
    after it has been repaired, no receipt with zero turnover was created as
    required.
    """

    def __init__(self, rec):
        super(NoRestoreReceiptAfterSignatureSystemFailureException, self).__init__(rec,
                _("Receipt after restored signature system must not have any turnover."))
        self._initargs = (rec,)

class InvalidTurnoverCounterException(DEPReceiptException):
    """
    This exception indicates that the turnover counter is invalid.
    """

    def __init__(self, rec):
        super(InvalidTurnoverCounterException, self).__init__(rec,
                _("Turnover counter invalid."))
        self._initargs = (rec,)

class ChangingRegisterIdException(DEPReceiptException):
    """
    This exception indicates that the register ID changed.
    """

    def __init__(self, rec):
        super(ChangingRegisterIdException, self).__init__(rec,
                _("Register ID changed."))
        self._initargs = (rec,)

class DecreasingDateException(DEPReceiptException):
    """
    This exception indicates that the date on the receipt is lower than
    the date on the previous receipt.
    """

    def __init__(self, rec):
        super(DecreasingDateException, self).__init__(rec,
                _("Receipt was created before previous receipt."))
        self._initargs = (rec,)

class ChangingSystemTypeException(DEPReceiptException):
    """
    This exception indicates that the type of the system (open/closed)
    changed.
    """

    def __init__(self, rec):
        super(ChangingSystemTypeException, self).__init__(rec,
                _("The system type changed."))
        self._initargs = (rec,)

class ChangingTurnoverCounterSizeException(DEPReceiptException):
    """
    This exception indicates that the size of the turnover counter
    changed.
    """

    def __init__(self, rec):
        super(ChangingTurnoverCounterSizeException, self).__init__(rec,
                _("The size of the turnover counter changed."))
        self._initargs = (rec,)

class NoCertificateGivenException(depparser.DEPException):
    """
    This exception indicates that a DEP using multiple receipt groups did not
    specify the used certificate for a group.
    """

    def __init__(self):
        super(NoCertificateGivenException, self).__init__(_("No certificate specified in DEP and multiple groups used."))
        self._initargs = ()

class UntrustedCertificateException(depparser.DEPException):
    """
    This exception indicates that neither the used certificate (or public key)
    nor any of the certificates in the certificate chain is available in the
    used key store.
    """

    def __init__(self, cert):
        super(UntrustedCertificateException, self).__init__(
                _("Certificate \"%s\" is not trusted.") % cert)
        self._initargs = (cert,)

class CertificateChainBrokenException(depparser.DEPException):
    """
    This exception indicates that a given certificate chain is broken at
    the given certificate (i.e. the certificate was not properly signed
    by the next in the chain).
    """

    def __init__(self, cert, sign):
        super(CertificateChainBrokenException, self).__init__(
                _("Certificate \"{}\" was not signed by \"{}\".").format(
                    cert, sign))
        self._initargs = (cert, sign)

class CertificateSerialCollisionException(depparser.DEPException):
    """
    This exception indicates that two certificates with matching serials but
    different fingerprints were detected which could indicate an attempted attack.
    """

    def __init__(self, serial, cert1FP, cert2FP):
        super(CertificateSerialCollisionException, self).__init__(
                _("Two certificates with serial \"{0}\" detected (fingerprints \"{1}\" and \"{2}\"). This may be an attempted attack.").format(
                    serial, cert1FP, cert2FP))
        self._initargs = (serial, cert1FP, cert2FP)

class SignatureSystemFailedOnInitialReceiptException(DEPReceiptException):
    """
    Indicates that the initial receipt was not signed.
    """
    def __init__(self, rec):
        super(SignatureSystemFailedOnInitialReceiptException, self).__init__(rec,
                _("Initial receipt not signed."))
        self._initargs = (rec,)

class NonzeroTurnoverOnInitialReceiptException(DEPReceiptException):
    """
    Indicates that the initial receipt has a nonzero turnover.
    """
    def __init__(self, rec):
        super(NonzeroTurnoverOnInitialReceiptException, self).__init__(
                rec, _("Initial receipt has nonzero turnover."))
        self._initargs = (rec,)

class InvalidChainingOnInitialReceiptException(DEPReceiptException):
    """
    Indicates that the initial receipt has not been chained to the cash
    register ID.
    """
    def __init__(self, rec):
        super(InvalidChainingOnInitialReceiptException, self).__init__(
                rec,
                _("Initial receipt has not been chained to the cash register ID."))
        self._initargs = (rec,)

class InvalidChainingOnClusterInitialReceiptException(DEPReceiptException):
    """
    Indicates that the initial receipt of a GGS cluster register has not
    been chained to the previous cash register's initial receipt.
    """
    def __init__(self, rec):
        super(InvalidChainingOnClusterInitialReceiptException, self).__init__(
                rec,
                _("Initial receipt in cluster has not been chained to the previous cash register's initial receipt."))
        self._initargs = (rec,)

class NonstandardTypeOnInitialReceiptException(DEPReceiptException):
    """
    Indicates that the initial receipt is a dummy or reversal receipt.
    """
    def __init__(self, rec):
        super(NonstandardTypeOnInitialReceiptException, self).__init__(
                rec,
                _("Initial receipt is a dummy or reversal receipt."))
        self._initargs = (rec,)

def verifyChainValue(rec, chainingValue):
    if chainingValue != rec.previousChain:
        raise ChainingException(rec.receiptId, rec.previousChain)

def verifyChain(rec, prev, algorithm):
    """
    Verifies that a receipt is preceeded by another receipt in the receipt
    chain. It returns nothing on success and throws an exception otherwise.
    :param rec: The new receipt as a receipt object.
    :param prev: The previous receipt as a JWS string or None if this is
    the first receipt.
    :param algorithm: The algorithm class to use.
    :throws: ChainingException
    """
    chainingValue = algorithm.chain(rec, prev)
    chainingValue = base64.b64encode(chainingValue)
    verifyChainValue(rec, chainingValue.decode('utf-8'));

def verifyCert(cert, chain, keyStore):
    """
    Verifies that a certificate or one of its signers is in the given key store.
    Returns nothing on success and throws an exception otherwise.
    :param cert: The certificate to verify as an object.
    :param chain: A list of certificates as objects. These represent the
    signing chain for the certificate.
    :param keyStore: The key store.
    :throws: UntrustedCertificateException
    :throws: CertificateSerialCollisionException
    :throws: CertificateChainBrokenException
    """
    prev = cert

    for c in chain:
        ksCert = keyStore.getCert(key_store.numSerialToKeyId(prev.serial_number))
        if ksCert:
            if utils.certFingerprint(ksCert) != utils.certFingerprint(prev):
                raise CertificateSerialCollisionException(
                        key_store.numSerialToKeyId(prev.serial_number),
                        utils.certFingerprint(prev),
                        utils.certFingerprint(ksCert))
            return

        if not utils.verifyCert(prev, c):
            raise CertificateChainBrokenException(
                    key_store.numSerialToKeyId(prev.serial_number),
                    key_store.numSerialToKeyId(c.serial_number))

        prev = c

    ksCert = keyStore.getCert(key_store.numSerialToKeyId(prev.serial_number))
    if ksCert:
        if utils.certFingerprint(ksCert) != utils.certFingerprint(prev):
            raise CertificateSerialCollisionException(
                    key_store.numSerialToKeyId(prev.serial_number),
                    utils.certFingerprint(prev),
                    utils.certFingerprint(ksCert))
        return

    raise UntrustedCertificateException(key_store.numSerialToKeyId(
        cert.serial_number))

def verifyGroup(group, rv, key, prevStartReceiptJWS, cashRegisterState,
        usedReceiptIds, reinit):
    """
    Verifies a group of receipts from a DEP. It checks if the signature of
    each receipt is valid, if the receipts are properly chained and if
    receipts with zero turnover are present as required. If a key is
    specified it also verifies the turnover counter.
    :param group: The receipts in the group as a list of compressed JWS strings
    as returned by a parser conforming to depparser.DEPParserI.
    :param rv: The receipt verifier object used to verify single receipts.
    :param key: The key used to decrypt the turnover counter as a byte list
    or None.
    :param prevStartReceiptJWS: The start receipt (in JWS format) of the
    previous cash register in the GGS cluster or None if there is no
    cluster or the register is the first in one. This is only used if
    cashRegisterState does not contain a previous receipt for the register.
    :param cashRegisterState: State of the cash register as a
    CashRegisterState object. This object is updated after every successfully
    checked receipt.
    :param usedReceiptIds: A set containing all previously used receipt IDs
    as strings. Note that this set is not per DEP or per cash register but
    per GGS cluster. It is also updated after every successfully checked
    receipt.
    :param reinit: If true, verifyGroup will use the information in the state
    and the first receipt in the group to construct a state against which that
    first receipt will definitely pass verification. This is used to continue
    after a detected error. Otherwise, the state is used as is.
    :throws: NoRestoreReceiptAfterSignatureSystemFailure
    :throws: InvalidTurnoverCounterException
    :throws: CertSerialInvalidException
    :throws: CertSerialMismatchException
    :throws: NoPublicKeyException
    :throws: InvalidSignatureException
    :throws: ChainingException
    :throws: MalformedReceiptException
    :throws: UnknownAlgorithmException
    :throws: AlgorithmMismatchException
    :throws: SignatureSystemFailedOnInitialReceiptException
    :throws: UnsignedNullReceiptException
    :throws: NonzeroTurnoverOnInitialReceiptException
    :throws: InvalidChainingOnInitialReceiptException
    :throws: NonstandardTypeOnInitialReceiptException
    :throws: ChangingRegisterIdException
    :throws: DecreasingDateException
    :throws: ChangingSystemTypeException
    :throws: ChangingTurnoverCounterSizeException
    :throws: DuplicateReceiptIdException
    :throws: ClusterInOpenSystemException
    """
    if not cashRegisterState:
        raise Exception(_('THIS IS A BUG'))
    if not usedReceiptIds:
        raise Exception(_('THIS IS A BUG'))

    if reinit:
        reRec, rePre = receipt.Receipt.fromJWSString(
                depparser.expandDEPReceipt(group[0]))
        cashRegisterState.updateForReceipt(reRec, rePre, key)

    prev = cashRegisterState.lastReceiptJWS
    prevObj = None
    if prev:
        prevObj, algorithmPrefix = receipt.Receipt.fromJWSString(prev)
    while group:
        cr = group[0]
        r = depparser.expandDEPReceipt(cr)
        ro = None
        algorithm = None

        # record a start receipt as soon as we expand it
        if not prevObj:
            cashRegisterState.startReceiptJWS = r

        needRestoreReceipt = cashRegisterState.needRestoreReceipt
        try:
            ro, algorithm = rv.verifyJWS(r)
            if prevObj and (not ro.isNull() or ro.isDummy() or ro.isReversal()):
                if needRestoreReceipt:
                    raise NoRestoreReceiptAfterSignatureSystemFailureException(ro.receiptId)
                if prevObj.isSignedBroken():
                    needRestoreReceipt = True
            else:
                needRestoreReceipt = False
        except verify_receipt.SignatureSystemFailedException as e:
            pass
        except verify_receipt.UnsignedNullReceiptException as e:
            pass

        # Exception occured and was caught
        if not ro:
            ro, algorithmPrefix = receipt.Receipt.fromJWSString(r)
            if not prevObj:
                raise SignatureSystemFailedOnInitialReceiptException(ro.receiptId)
            if needRestoreReceipt:
                raise NoRestoreReceiptAfterSignatureSystemFailureException(ro.receiptId)
            # fromJWSString() already raises an UnknownAlgorithmException if necessary
            algorithm = algorithms.ALGORITHMS[algorithmPrefix]

        if not prevObj:
            if not ro.isNull():
                raise NonzeroTurnoverOnInitialReceiptException(ro.receiptId)
            if ro.isDummy() or ro.isReversal():
                raise NonstandardTypeOnInitialReceiptException(ro.receiptId)

            # We are checking a DEP in a GGS cluster.
            if prevStartReceiptJWS:
                if ro.zda != 'AT0':
                    raise ClusterInOpenSystemException()
                prev = prevStartReceiptJWS
                prevObj, algorithmPrefix = receipt.Receipt.fromJWSString(prev)
                if prevObj.zda != 'AT0':
                    raise ClusterInOpenSystemException()

        if prevObj:
            if prevObj.registerId != ro.registerId:
                raise ChangingRegisterIdException(ro.receiptId)
            if (prevObj.zda == 'AT0' and ro.zda != 'AT0') or (
                    prevObj.zda != 'AT0' and ro.zda == 'AT0'):
                raise ChangingSystemTypeException(ro.receiptId)
            # These checks are not necessary according to:
            # https://github.com/BMF-RKSV-Technik/at-registrierkassen-mustercode/issues/144#issuecomment-255786335
            # However, the current (v1.1.1) BMF tool enforces this anyway so we
            # will too.
            if prevObj.dateTime > ro.dateTime:
                raise DecreasingDateException(ro.receiptId)

        try:
            if cashRegisterState.chainNextTo:
                verifyChainValue(ro, cashRegisterState.chainNextTo)
            else:
                verifyChain(ro, prev, algorithm)
        except ChainingException as e:
            # Special exception for the initial receipt
            if cashRegisterState.startReceiptJWS == r:
                if prevStartReceiptJWS:
                    raise InvalidChainingOnClusterInitialReceiptException(e.receipt)
                raise InvalidChainingOnInitialReceiptException(e.receipt)
            raise e

        newC = cashRegisterState.lastTurnoverCounter
        if not ro.isDummy():
            if key is not None:
                utils.raiseForKey(key, algorithm)
                newC += int(round((ro.sumA + ro.sumB + ro.sumC + ro.sumD
                    + ro.sumE) * 100))
                if not ro.isReversal():
                    turnoverCounter = ro.decryptTurnoverCounter(key, algorithm)
                    if turnoverCounter != newC:
                        raise InvalidTurnoverCounterException(ro.receiptId)

        # update the cash register state
        cashRegisterState.needRestoreReceipt = needRestoreReceipt
        cashRegisterState.chainNextTo = None
        cashRegisterState.lastTurnoverCounter = newC
        cashRegisterState.lastReceiptJWS = r

        prev = r
        prevObj = ro

        # remove the handled receipt from the group
        group.pop(0)

        # check and update the used receipt IDs
        # This goes last so if we have a duplicate receipt we can just call
        # verifyGroup again.
        usedReceiptIds.check(ro.receiptId)
        usedReceiptIds.add(ro.receiptId)

def verifyGroupsWithVerifiers(args):
    groups, key, prevStart, rState, usedRecIds = args

    """
    Takes a list of tuples containing a list of receipts and their
    according ReceiptVerifier each and calls verifyGroup() for each of
    those tuples passing the register state and used receipt IDs along for
    each call.
    :param groups: The list of tuples. The first element of each tuple is a
    list of receipts as returned by a parser conforming to
    depparser.DEPParserI, the second element is a ReceiptVerifier object
    intented to verify all receipts in the list.
    :param key: The key used to decrypt the turnover counter as a byte list
    or None.
    :param prevStart: The start receipt (in JWS format) of the previous
    cash register in the GGS cluster or None if there is no cluster or the
    register is the first in one. This is only used if rState does not
    contain a previous receipt for the register.
    :param rState: State of the cash register as a CashRegisterState
    object.
    :param usedRecIds: A set containing all previously used receipt IDs as
    strings. Note that this set is not per DEP or per cash register but per
    GGS cluster.
    :return: The updated rState object and the updated usedRecIds set, as well
    as an RKSVVerifyMultiException (which is empty if no errors occurred). The
    former two can be passed to a subsequent call to verifyGroup() or
    verifyGroupsWithVerifiers().
    :throws: NoRestoreReceiptAfterSignatureSystemFailure
    :throws: InvalidTurnoverCounterException
    :throws: CertSerialInvalidException
    :throws: CertSerialMismatchException
    :throws: NoPublicKeyException
    :throws: InvalidSignatureException
    :throws: ChainingException
    :throws: MalformedReceiptException
    :throws: UnknownAlgorithmException
    :throws: AlgorithmMismatchException
    :throws: SignatureSystemFailedOnInitialReceiptException
    :throws: UnsignedNullReceiptException
    :throws: NonzeroTurnoverOnInitialReceiptException
    :throws: InvalidChainingOnInitialReceiptException
    :throws: NonstandardTypeOnInitialReceiptException
    :throws: ChangingRegisterIdException
    :throws: DecreasingDateException
    :throws: ChangingSystemTypeException
    :throws: ChangingTurnoverCounterSizeException
    :throws: DuplicateReceiptIdException
    :throws: ClusterInOpenSystemException
    """
    # exit on the first detected error
    for recs, rv in groups:
        verifyGroup(recs, rv, key, prevStart, rState, usedRecIds, False)
    return rState, usedRecIds, utils.RKSVVerifyMultiException()

def verifyGroupsWithVerifiersMulti(args):
    groups, key, prevStart, rState, usedRecIds = args

    # collect errors we can recover from and continue
    error = utils.RKSVVerifyMultiException()
    reinit = False
    for recs, rv in groups:
        while len(recs) > 0:
            try:
                verifyGroup(recs, rv, key, prevStart, rState, usedRecIds, reinit)
                reinit = False
                break
            except DEPReceiptException as e:
                error.appendVerifyError(e)
            except receipt.ReceiptException as e:
                error.appendVerifyError(e)
                recs.pop(0)
            except verification_state.DuplicateReceiptIdException as e:
                error.appendVerifyError(e)
                # don't reinit, all other checks passed for this receipt, just
                # continue
                continue

            reinit = True

    return rState, usedRecIds, error

def balanceGroupsWithVerifiers(groups, nprocs):
    """
    Takes a list of tuples with lists of receipts and their according
    ReceiptVerifiers and returns a list of at most nprocs packages with
    each package containing a such a list of tuples. Each package should be
    roughly of equal size with the last one possibly being smaller than the
    rest. This function is intended to split the workload for verifying a
    DEP into nprocs packages of equal size which can then be assigned to
    multiple worker processes.
    :param groups: The list of tuples. The first element of each tuple is a
    list of receipts as returned by a parser conforming to
    depparser.DEPParserI, the second element is a ReceiptVerifier object
    intented to verify all receipts in the list.
    :param nprocs: The maximum number of packages to create.
    :return: The list of packages. Each package in turn contains a list
    structured like the groups parameter.
    """
    recsWithVerifiers = [ (r, rv) for recs, rv in groups for r in recs ]

    recsPerProc = int(ceil(float(len(recsWithVerifiers)) / nprocs))
    subs = [ recsWithVerifiers[i:i + recsPerProc] for i in range(0,
        len(recsWithVerifiers), recsPerProc) ]

    pkgs = list()
    for sub in subs:
        groups = list()
        for rv, recsAndVerifiers in groupby(sub, lambda x: x[1]):
            recs = [ r for r, v in recsAndVerifiers ]
            groups.append((recs, rv))
        pkgs.append(groups)

    return pkgs

def packageChunkWithVerifiers(chunk, keyStore):
    groupsWithVerifiers = list()
    if len(chunk) == 1:
        recs, cert, chain = chunk[0]
        if not cert:
            rv = verify_receipt.ReceiptVerifier.fromKeyStore(keyStore)
        else:
            verifyCert(cert, chain, keyStore)
            rv = verify_receipt.ReceiptVerifier.fromCert(cert)

        groupsWithVerifiers.append((recs, rv))
    else:
        for recs, cert, chain in chunk:
            if not cert:
                raise NoCertificateGivenException()
            verifyCert(cert, chain, keyStore)
            rv = verify_receipt.ReceiptVerifier.fromCert(cert)
            groupsWithVerifiers.append((recs, rv))
    return groupsWithVerifiers

def getChunksForProcs(allChunks, nprocs):
    ret = list()
    for chunk in allChunks:
        ret.append(chunk)
        chunk = None
        if len(ret) >= nprocs:
            yield ret
            ret = list()

    if len(ret) > 0:
        yield ret

def prepareVerificationTuples(chunksWithVerifiers, key, prevStartJWS,
        cashregState, usedRecIdsBackend):
    # create start cashreg state for each package
    npkgs = len(chunksWithVerifiers)
    nextGroupReinit = False
    pkgRStates = [cashregState]
    pkgRState = cashregState
    for pkg in chunksWithVerifiers:
        pkgRState = copy.copy(pkgRState)

        for group, rv in pkg:
            if nextGroupReinit and len(group) > 0:
                # The update from the last group failed. Reconstruct the state
                # from the first receipt of this one if possible.
                try:
                    ro, prefix = receipt.Receipt.fromJWSString(
                            depparser.expandDEPReceipt(group[0]))
                    pkgRState.updateForReceipt(ro, prefix, key)
                except receipt.ReceiptException:
                    pass
                nextGroupReinit = False

            try:
                pkgRState.updateFromDEPGroup(group, key)
            except receipt.ReceiptException:
                nextGroupReinit = True

        pkgRStates.append(pkgRState)
    del pkgRStates[-1]

    return zip(chunksWithVerifiers, [key] * npkgs, [prevStartJWS] * npkgs,
            pkgRStates, [usedRecIdsBackend()] * npkgs)

def verifyParsedDEP(parser, keyStore, key, state = None,
        cashRegisterIdx = None, pool = None, nprocs = 1,
        chunksize = utils.depParserChunkSize(),
        usedRecIdsBackend = verification_state.DEFAULT_USED_RECEIPT_IDS_BACKEND,
        keepGoing = False):
    """
    Verifies a previously parsed DEP. It checks if the signature of each
    receipt is valid, if the receipts are properly chained, if receipts
    with zero turnover are present as required and if the certificates used
    to sign the receipts are valid. If a key is specified it also verifies
    the turnover counter. It does not check for errors that should already
    be detected while parsing the DEP.
    :param parser: A parser object confirming to depparser.DEPParserI.
    :param keyStore: The key store object containing the used public keys and
    certificates.
    :param key: The key used to decrypt the turnover counter as a byte list or
    None.
    :param state: The state returned by evaluating a previous DEP or None.
    :param cashRegisterIdx: The index of the cash register that created the
    DEP in the state parameter or None to create a new register state.
    :param pool: A pool of processes to distribute the work of verifying a
    DEP among. The pool must support the map() function. If no pool is
    specified, the current process will perform all the work itself.
    :param nprocs: The number of processes to expect/use in pool. This
    function will create at most nprocs work packages at a time and either pass
    them to a pool or (if no pool is given) process them itself. How the
    packages are distributed among the pool's processes is up to the pool.
    :param chunksize: The number of receipts the parser should read from the DEP
    in one go.
    :param usedRecIdsBackend: The implementation used to keep track of used
    receipt IDs.
    :return: The state of the evaluation. (Can be used for the next DEP.)
    :throws: NoRestoreReceiptAfterSignatureSystemFailure
    :throws: InvalidTurnoverCounterException
    :throws: CertSerialInvalidException
    :throws: CertSerialMismatchException
    :throws: NoPublicKeyException
    :throws: InvalidSignatureException
    :throws: ChainingException
    :throws: MalformedReceiptException
    :throws: UnknownAlgorithmException
    :throws: AlgorithmMismatchException
    :throws: UntrustedCertificateException
    :throws: CertificateSerialCollisionException
    :throws: SignatureSystemFailedOnInitialReceiptException
    :throws: UnsignedNullReceiptException
    :throws: NonzeroTurnoverOnInitialReceiptException
    :throws: NoCertificateGivenException
    :throws: InvalidChainingOnInitialReceiptException
    :throws: NonstandardTypeOnInitialReceiptException
    :throws: ChangingRegisterIdException
    :throws: ChangingSystemTypeException
    :throws: CertificateChainBrokenException
    :throws: DuplicateReceiptIdException
    :throws: ClusterInOpenSystemException
    :throws: InvalidCashRegisterIndexException
    :throws: NoStartReceiptForLastCashRegisterException
    :throws: depparser.DEPParseException
    """
    if keepGoing:
        verifyGroupsFunc = verifyGroupsWithVerifiersMulti
    else:
        verifyGroupsFunc = verifyGroupsWithVerifiers

    if not state:
        state = verification_state.ClusterState(usedRecIdsBackend)

    # Use the same backend in all processes so we don't have to do merging
    # across different backends.
    usedRecIdsBackend = state.usedReceiptIds.__class__

    prevStart, rState, usedRecIds = state.getCashRegisterInfo(cashRegisterIdx)
    errors = utils.RKSVVerifyMultiException()
    res = None
    for chunks in getChunksForProcs(parser.parse(chunksize), nprocs):
        pkgs = [ packageChunkWithVerifiers(chunk, keyStore) for chunk in chunks ]

        if res is not None:
            outRStates, outUsedRecIds, outErrors = zip(*res.get())
            # collapse detected errors into a single exception
            for outE in outErrors:
                errors.extendVerifyError(outE)
            usedRecIds.merge(outUsedRecIds)
            rState = outRStates[-1]

        wargs = prepareVerificationTuples(pkgs, key, prevStart, rState,
                usedRecIdsBackend)

        # apply verifyGroup() to each package
        if not pool:
            outresults = map(verifyGroupsFunc, wargs)
            res = type('DummyAsyncResult', (object,), {"data": outresults})
            res.get = MethodType(lambda self: self.data, res)
        else:
            res = pool.map_async(verifyGroupsFunc, wargs)

    outRStates, outUsedRecIds, outErrors = zip(*res.get())
    # collapse detected errors into a single exception
    for outE in outErrors:
        errors.extendVerifyError(outE)
    usedRecIds.merge(outUsedRecIds)
    rState = outRStates[-1]

    state.updateCashRegisterInfo(cashRegisterIdx, rState, usedRecIds)

    if errors.hasErrors():
        return state, errors
    return state, None

# TODO: throw this out?
def verifyDEP(dep, keyStore, key, state = None, cashRegisterIdx = None,
        usedRecIdsBackend = verification_state.DEFAULT_USED_RECEIPT_IDS_BACKEND):
    """
    Verifies an entire DEP. It checks if the signature of each receipt is
    valid, if the receipts are properly chained, if receipts with zero
    turnover are present as required and if the certificates used to sign
    the receipts are valid. If a key is specified it also verifies the
    turnover counter.
    :param dep: The DEP as a json object.
    :param keyStore: The key store object containing the used public keys
    and certificates.
    :param key: The key used to decrypt the turnover counter as a byte list
    or None.
    :param state: The state returned by evaluating a previous DEP or None.
    :param cashRegisterIdx: The index of the cash register that created the
    DEP in the state parameter or None to create a new register state.
    :param usedRecIdsBackend: The implementation used to keep track of used
    receipt IDs.
    :return: The state of the evaluation. (Can be used for the next DEP.)
    :throws: NoRestoreReceiptAfterSignatureSystemFailure
    :throws: InvalidTurnoverCounterException
    :throws: CertSerialInvalidException
    :throws: CertSerialMismatchException
    :throws: NoPublicKeyException
    :throws: InvalidSignatureException
    :throws: ChainingException
    :throws: MalformedReceiptException
    :throws: UnknownAlgorithmException
    :throws: AlgorithmMismatchException
    :throws: UntrustedCertificateException
    :throws: CertificateSerialCollisionException
    :throws: SignatureSystemFailedOnInitialReceiptException
    :throws: UnsignedNullReceiptException
    :throws: NonzeroTurnoverOnInitialReceiptException
    :throws: NoCertificateGivenException
    :throws: InvalidChainingOnInitialReceiptException
    :throws: NonstandardTypeOnInitialReceiptException
    :throws: ChangingRegisterIdException
    :throws: ChangingSystemTypeException
    :throws: CertificateChainBrokenException
    :throws: DuplicateReceiptIdException
    :throws: ClusterInOpenSystemException
    :throws: InvalidCashRegisterIndexException
    :throws: NoStartReceiptForLastCashRegisterException
    :throws: depparser.DEPParseException
    """
    if not state:
        state = verification_state.ClusterState(usedRecIdsBackend)

    prevStart, rState, usedRecIds = state.getCashRegisterInfo(
            cashRegisterIdx)

    # FIXME: ewww...
    one_group = None
    for chunk in depparser.DictDEPParser(dep).parse(0):
        if len(chunk) < 1:
            raise Exception(_('THIS IS A BUG'))

        for recs, cert, chain in chunk:
            if one_group:
                raise NoCertificateGivenException()

            if one_group:
                raise NoCertificateGivenException()

            if not cert:
                if one_group == False:
                    raise NoCertificateGivenException()
                rv = verify_receipt.ReceiptVerifier.fromKeyStore(keyStore)
                one_group = True
            else:
                verifyCert(cert, chain, keyStore)
                rv = verify_receipt.ReceiptVerifier.fromCert(cert)
                one_group = False

            verifyGroup(recs, rv, key, prevStart, rState, usedRecIds, False)

    state.updateCashRegisterInfo(cashRegisterIdx, rState, usedRecIds)
    return state
