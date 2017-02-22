#!/usr/bin/env python2.7

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

"""
This module provides functions to verify a DEP.
"""

from __future__ import print_function
from builtins import int
from builtins import range

import base64

from itertools import groupby
from math import ceil
from six import string_types

import algorithms
import key_store
import receipt
import utils
import verification_state
import verify_receipt

class DEPException(Exception):
    """
    An exception that is thrown if something is wrong with a DEP.
    """
    def __init__(self, message):
        super(DEPException, self).__init__(message)
        self._initargs = (message,)

    def __reduce__(self):
        return (self.__class__, self._initargs)

class MalformedDEPException(DEPException):
    """
    Indicates that the DEP is not properly formed.
    """

    def __init__(self, msg=None):
        super(MalformedDEPException, self).__init__(
                msg if msg else _("Malformed DEP"))
        self._initargs = (msg,)

class MalformedCertificateException(DEPException):
    """
    Indicates that the DEP is not properly formed.
    """

    def __init__(self, cert):
        super(MalformedCertificateException, self).__init__(
                _("Malformed certificate: \"{}\"").format(cert))
        self._initargs = (cert,)

class DEPElementMissingException(MalformedDEPException):
    """
    Indicates that the DEP is not properly formed.
    """

    def __init__(self, elem):
        super(DEPElementMissingException, self).__init__(
                _("Element \"{}\" missing from DEP").format(elem))
        self._initargs = (elem,)

class ClusterInOpenSystemException(DEPException):
    """
    This exception indicates that a cluster of cash registers was
    detected in an open system.
    """

    def __init__(self):
        super(ClusterInOpenSystemException, self).__init__(
                _("GGS Cluster is not supported in an open system."))
        self._initargs = ()

class DEPReceiptException(DEPException):
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
                _("Previous receipt is not \"{0}\".").format(recPrev))
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

class DuplicateReceiptIdException(DEPReceiptException):
    """
    This exception indicates that the ID of a receipt is already in use in
    a previous receipt.
    """

    def __init__(self, rec):
        super(DuplicateReceiptIdException, self).__init__(rec,
                _("Receipt ID already in use."))
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

class NoCertificateGivenException(DEPException):
    """
    This exception indicates that a DEP using multiple receipt groups did not
    specify the used certificate for a group.
    """

    def __init__(self):
        super(NoCertificateGivenException, self).__init__(_("No certificate specified in DEP and multiple groups used."))
        self._initargs = ()

class UntrustedCertificateException(DEPException):
    """
    This exception indicates that neither the used certificate (or public key)
    nor any of the certificates in the certificate chain is available in the
    used key store.
    """

    def __init__(self, cert):
        super(UntrustedCertificateException, self).__init__(
                _("Certificate \"%s\" is not trusted.") % cert)
        self._initargs = (cert,)

class CertificateChainBrokenException(DEPException):
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

class CertificateSerialCollisionException(DEPException):
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

class InvalidChainingOnClusterInitialReceiptException(InvalidChainingOnInitialReceiptException):
    """
    Indicates that the initial receipt of a GGS cluster register has not
    been chained to the previous cash register's initial receipt.
    """
    def __init__(self, rec):
        super(InvalidChainingOnInitialReceiptException, self).__init__(
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
    if chainingValue.decode("utf-8") != rec.previousChain:
        raise ChainingException(rec.receiptId, prev)

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
        ksCert = keyStore.getCert(key_store.numSerialToKeyId(prev.serial))
        if ksCert:
            if utils.certFingerprint(ksCert) != utils.certFingerprint(prev):
                raise CertificateSerialCollisionException(
                        key_store.numSerialToKeyId(prev.serial),
                        utils.certFingerprint(prev),
                        utils.certFingerprint(ksCert))
            return

        if not utils.verifyCert(prev, c):
            raise CertificateChainBrokenException(
                    key_store.numSerialToKeyId(prev.serial),
                    key_store.numSerialToKeyId(c.serial))

        prev = c

    ksCert = keyStore.getCert(key_store.numSerialToKeyId(prev.serial))
    if ksCert:
        if utils.certFingerprint(ksCert) != utils.certFingerprint(prev):
            raise CertificateSerialCollisionException(
                    key_store.numSerialToKeyId(prev.serial),
                    utils.certFingerprint(prev),
                    utils.certFingerprint(ksCert))
        return

    raise UntrustedCertificateException(key_store.numSerialToKeyId(
        cert.serial))

def verifyGroup(group, rv, key, prevStartReceiptJWS = None,
        cashRegisterState=None, usedReceiptIds = None):
    """
    Verifies a group of receipts from a DEP. It checks if the signature of
    each receipt is valid, if the receipts are properly chained and if
    receipts with zero turnover are present as required. If a key is
    specified it also verifies the turnover counter.
    :param group: The receipts in the group as a list of compressed JWS strings
    as returned by parseDEPGroup().
    :param rv: The receipt verifier object used to verify single receipts.
    :param key: The key used to decrypt the turnover counter as a byte list
    or None.
    :param prevStartReceiptJWS: The start receipt (in JWS format) of the
    previous cash register in the GGS cluster or None if there is no
    cluster or the register is the first in one. This is only used if
    cashRegisterState does not contain a previous receipt for the register.
    :param cashRegisterState: State of the cash register as a
    CashRegisterState object.
    :param usedReceiptIds: A set containing all previously used receipt IDs
    as strings. Note that this set is not per DEP or per cash register but
    per GGS cluster.
    :return: The updated cashRegisterState object and the updated
    usedReceiptIds set. These can be passed to a subsequent call to
    verifyGroup().
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
        cashRegisterState = verification_state.CashRegisterState()
    if not usedReceiptIds:
        usedReceiptIds = set()

    prev = cashRegisterState.lastReceiptJWS
    prevObj = None
    if prev:
        prevObj, algorithmPrefix = receipt.Receipt.fromJWSString(prev)
    for cr in group:
        r = expandDEPReceipt(cr)
        ro = None
        algorithm = None
        try:
            ro, algorithm = rv.verifyJWS(r)
            if prevObj and (not ro.isNull() or ro.isDummy() or ro.isReversal()):
                if cashRegisterState.needRestoreReceipt:
                    raise NoRestoreReceiptAfterSignatureSystemFailureException(ro.receiptId)
                if prevObj.isSignedBroken():
                    cashRegisterState.needRestoreReceipt = True
            else:
                cashRegisterState.needRestoreReceipt = False
        except verify_receipt.SignatureSystemFailedException as e:
            pass
        except verify_receipt.UnsignedNullReceiptException as e:
            pass

        # Exception occured and was caught
        if not ro:
            ro, algorithmPrefix = receipt.Receipt.fromJWSString(r)
            if not prevObj:
                raise SignatureSystemFailedOnInitialReceiptException(ro.receiptId)
            if cashRegisterState.needRestoreReceipt:
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

            cashRegisterState.startReceiptJWS = r

        if prevObj:
            if ro.receiptId in usedReceiptIds:
                raise DuplicateReceiptIdException(ro.receiptId)
            if prevObj.registerId != ro.registerId:
                raise ChangingRegisterIdException(ro.receiptId)
            if (prevObj.zda == 'AT0' and ro.zda != 'AT0') or (
                    prevObj.zda != 'AT0' and ro.zda == 'AT0'):
                raise ChangingSystemTypeException(ro.receiptId)
            # These checks are not necessary according to:
            # https://github.com/a-sit-plus/at-registrierkassen-mustercode/issues/144#issuecomment-255786335
            #if prevObj.dateTime > ro.dateTime:
            #    raise DecreasingDateException(ro.receiptId)

        usedReceiptIds.add(ro.receiptId)

        try:
            verifyChain(ro, prev, algorithm)
        except ChainingException as e:
            # Special exception for the initial receipt
            if cashRegisterState.startReceiptJWS == r:
                if prevStartReceiptJWS:
                    raise InvalidChainingOnClusterInitialReceiptException(e.receipt)
                raise InvalidChainingOnInitialReceiptException(e.receipt)
            raise e

        if not ro.isDummy():
            if key:
                newC = cashRegisterState.lastTurnoverCounter + int(round(
                    (ro.sumA + ro.sumB + ro.sumC + ro.sumD + ro.sumE) * 100))
                if not ro.isReversal():
                    turnoverCounter = ro.decryptTurnoverCounter(key, algorithm)
                    if turnoverCounter != newC:
                        raise InvalidTurnoverCounterException(ro.receiptId)
                cashRegisterState.lastTurnoverCounter = newC

        prev = r
        prevObj = ro

    cashRegisterState.lastReceiptJWS = prev
    return cashRegisterState, usedReceiptIds

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

def shrinkDEPReceipt(rec):
    try:
        return rec.encode('utf-8')
    except TypeError:
        raise MalformedDEPException()

def expandDEPReceipt(rec):
    try:
        return rec.decode('utf-8')
    except UnicodeDecodeError:
        raise MalformedDEPException()

def parseDEPGroup(group):
    """
    Parses a single group from a DEP and return a tuple with its contents.
    :param group: The group as a JSON object.
    :return: A list of receipts as compressed (i.e. stored as encoded byte
    array) JWS strings (these are _not_ checked), a certificate object
    containing the certificate used to sign the receipts in this group (or None)
    and a list of certificate objects containing the certificates used to sign
    the group certificate.
    :throws: MalformedCertificateException
    :throws: MalformedDEPException
    :throws: DEPElementMissingException
    """
    if not isinstance(group, dict):
        raise MalformedDEPException()

    if 'Belege-kompakt' not in group:
        raise DEPElementMissingException('Belege-kompakt')

    cert_str = group.get('Signaturzertifikat', '')
    cert_str_list = group.get('Zertifizierungsstellen', [])
    # TODO: see if there is a smarter way to do this/do it during JSON parsing
    receipts = list(map(shrinkDEPReceipt, group['Belege-kompakt']))

    if (not isinstance(cert_str, string_types) or
            not isinstance(cert_str_list, list) or
            not isinstance(receipts, list)):
        raise MalformedDEPException()

    cert = parseDEPCert(cert_str) if cert_str != '' else None
    cert_list = [ parseDEPCert(cs) for cs in cert_str_list ]

    return receipts, cert, cert_list

def parseDEP(dep):
    """
    Retrieves the list of group elements from a JSON DEP. The group
    elements themselves are _not_ parsed.
    :param dep: The DEP as a JSON object.
    :return: A list containing the groups as JSON objects.
    :throws: MalformedDEPException
    :throws: DEPElementMissingException
    """
    if not isinstance(dep, dict):
        raise MalformedDEPException()
    if 'Belege-Gruppe' not in dep:
        raise DEPElementMissingException('Belege-Gruppe')

    bg = dep['Belege-Gruppe']
    if not isinstance(bg, list) or len(bg) <= 0:
        raise MalformedDEPException()

    return bg

def parseDEPAndGroups(dep):
    """
    Retrieves the list of groups from a JSON DEP and parses each group
    with parseDEPGroup().
    :param dep: The DEP as a JSON object.
    :return: A list containing a tuple as returned by parseDEPGroup() for
    each group.
    :throws: MalformedCertificateException
    :throws: MalformedDEPException
    :throws: DEPElementMissingException
    """
    return [parseDEPGroup(g) for g in parseDEP(dep)]

def verifyGroupsWithVerifiers(groups, key, prevStart = None,
        rState = None, usedRecIds = None):
    """
    Takes a list of tuples containing a list of receipts and their
    according ReceiptVerifier each and calls verifyGroup() for each of
    those tuples passing the register state and used receipt IDs along for
    each call.
    :param groups: The list of tuples. The first element of each tuple is a
    list of receipts as returned by parseDEPGroup(), the second element is
    a ReceiptVerifier object intented to verify all receipts in the list.
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
    :return: The updated rState object and the updated usedRecIds set.
    These can be passed to a subsequent call to verifyGroup() or
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
    for recs, rv in groups:
        rState, usedRecIds = verifyGroup(recs, rv, key, prevStart, rState,
                usedRecIds)

    return rState, usedRecIds

def verifyGroupsWithVerifiersTuple(args):
    """
    This function is used as an adapter for the process pool's map()
    function. It simply calls verifyGroupsWithVerifiers with the arguments
    given in the args tuple.
    """
    return verifyGroupsWithVerifiers(*args)

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
    list of receipts as returned by parseDEPGroup(), the second element is
    a ReceiptVerifier object intented to verify all receipts in the list.
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

def verifyParsedDEP_prepare(dep, keyStore, key, state = None,
        cashRegisterIdx = None, nprocs = 1):
    if not state:
        state = verification_state.ClusterState()

    prevStart, rState, usedRecIds = state.getCashRegisterInfo(
            cashRegisterIdx)

    groupsWithVerifiers = list()

    if len(dep) == 1:
        recs, cert, chain = dep[0]

        if not cert:
            rv = verify_receipt.ReceiptVerifier.fromKeyStore(keyStore)
        else:
            verifyCert(cert, chain, keyStore)
            rv = verify_receipt.ReceiptVerifier.fromCert(cert)

        groupsWithVerifiers.append((recs, rv))
    else:
        for recs, cert, chain in dep:
            if not cert:
                raise NoCertificateGivenException()

            verifyCert(cert, chain, keyStore)

            rv = verify_receipt.ReceiptVerifier.fromCert(cert)

            groupsWithVerifiers.append((recs, rv))

    # repackage recs and verifiers according to nproc
    pkgs = balanceGroupsWithVerifiers(groupsWithVerifiers, nprocs)
    npkgs = len(pkgs)

    # create start cashreg state for each package
    pkgRStates = [rState]
    pkgRState = rState
    for pkg in pkgs:
        for group, rv in pkg:
            pkgRState = verification_state.CashRegisterState.fromDEPGroup(
                    pkgRState, group, key)
        pkgRStates.append(pkgRState)
    del pkgRStates[-1]

    # prepare arguments for each worker
    return zip(pkgs, [key] * npkgs, [prevStart] * npkgs, pkgRStates,
            [set()] * npkgs), usedRecIds

def verifyParsedDEP_finalize(outUsedRecIds, usedRecIds):
    # merge usedRecIds and check for duplicates
    seen = set()
    for rids in [usedRecIds] + list(outUsedRecIds):
        for rid in rids:
            if rid in seen:
                raise DuplicateReceiptIdException(rid)
            else:
                seen.add(rid)

    mergedUsedRecIds = usedRecIds | set.union(*outUsedRecIds)

    return mergedUsedRecIds

def verifyParsedDEP(dep, keyStore, key, state = None,
        cashRegisterIdx = None, pool = None, nprocs = 1):
    """
    Verifies a previously parsed DEP. It checks if the signature of each
    receipt is valid, if the receipts are properly chained, if receipts
    with zero turnover are present as required and if the certificates used
    to sign the receipts are valid. If a key is specified it also verifies
    the turnover counter. It does not check for errors that should already
    be detected while parsing the DEP.
    :param dep: The DEP as returned by parseDEPAndGroups().
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
    function will create at most nprocs work packages and either pass them
    to a pool or (if no pool is given) process them itself. How the
    packages are distributed among the pool's processes is up to the pool.
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
    :throws: DecreasingDateException
    :throws: ChangingSystemTypeException
    :throws: ChangingTurnoverCounterSizeException
    :throws: CertificateChainBrokenException
    :throws: DuplicateReceiptIdException
    :throws: ClusterInOpenSystemException
    :throws: InvalidCashRegisterIndexException
    :throws: NoStartReceiptForLastCashRegisterException
    """
    if not state:
        state = verification_state.ClusterState()

    inargs, usedRecIds = verifyParsedDEP_prepare(dep, keyStore, key, state,
            cashRegisterIdx, nprocs = 1)

    # apply verifyGroup() to each package
    if not pool:
        outresults = map(verifyGroupsWithVerifiersTuple, inargs)
    else:
        outresults = pool.map(verifyGroupsWithVerifiersTuple, inargs)
    outRStates, outUsedRecIds = zip(*outresults)

    mergedUsedRecIds = verifyParsedDEP_finalize(outUsedRecIds, usedRecIds)

    # update with latest cashreg state and return
    state.updateCashRegisterInfo(cashRegisterIdx, outRStates[-1],
            mergedUsedRecIds)

    return state

def verifyDEP(dep, keyStore, key, state = None, cashRegisterIdx = None):
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
    :throws: DecreasingDateException
    :throws: ChangingSystemTypeException
    :throws: ChangingTurnoverCounterSizeException
    :throws: CertificateChainBrokenException
    :throws: DuplicateReceiptIdException
    :throws: MalformedCertificateException
    :throws: MalformedDEPException
    :throws: DEPElementMissingException
    :throws: ClusterInOpenSystemException
    :throws: InvalidCashRegisterIndexException
    :throws: NoStartReceiptForLastCashRegisterException
    """
    if not state:
        state = verification_state.ClusterState()

    prevStart, rState, usedRecIds = state.getCashRegisterInfo(
            cashRegisterIdx)

    bg = parseDEP(dep)

    if len(bg) == 1:
        recs, cert, chain = parseDEPGroup(bg[0])
        if not cert:
            rv = verify_receipt.ReceiptVerifier.fromKeyStore(keyStore)

            rState, usedRecIds = verifyGroup(recs, rv, key, prevStart,
                    rState, usedRecIds)

            state.updateCashRegisterInfo(cashRegisterIdx, rState,
                    usedRecIds)
            return state

    for group in bg:
        recs, cert, chain = parseDEPGroup(group)

        if not cert:
            raise NoCertificateGivenException()

        verifyCert(cert, chain, keyStore)

        rv = verify_receipt.ReceiptVerifier.fromCert(cert)
    
        rState, usedRecIds = verifyGroup(recs, rv, key, prevStart,
                rState, usedRecIds)

    state.updateCashRegisterInfo(cashRegisterIdx, rState, usedRecIds)
    return state

def usage():
    print("Usage: ./verify.py [state [continue|<n>]] [par <n>] keyStore <key store> <dep export file> [<base64 AES key file>]",
            file=sys.stderr)
    print("       ./verify.py [state [continue|<n>]] [par <n>] json <json container file> <dep export file>",
            file=sys.stderr)
    print("       ./verify.py state", file=sys.stderr)
    sys.exit(0)

if __name__ == "__main__":
    import gettext
    gettext.install('rktool', './lang', True)

    import configparser
    import json
    import sys

    import key_store

    if len(sys.argv) < 2 or len(sys.argv) > 9:
        usage()

    key = None
    keyStore = None

    statePassthrough = False
    continueLast = False
    registerIdx = None
    if sys.argv[1] == 'state':
        statePassthrough = True
        del sys.argv[1]

    if statePassthrough and len(sys.argv) == 1:
        print(json.dumps(
            verification_state.ClusterState().writeStateToJson(),
            sort_keys=False, indent=2))
        sys.exit(0)

    if sys.argv[1] == 'continue':
        continueLast = True
        del sys.argv[1]
    else:
        try:
            registerIdx = int(sys.argv[1])
            del sys.argv[1]
        except ValueError:
            pass

    if len(sys.argv) < 4 or len(sys.argv) > 7:
        usage()

    nprocs = 1
    if sys.argv[1] == 'par':
        del sys.argv[1]
        try:
            nprocs = int(sys.argv[1])
            del sys.argv[1]
        except ValueError:
            usage()
    if nprocs < 1:
        usage()

    if len(sys.argv) < 4 or len(sys.argv) > 5:
        usage()

    if sys.argv[1] == 'keyStore':
        if len(sys.argv) == 5:
            with open(sys.argv[4]) as f:
                key = base64.b64decode(f.read().encode("utf-8"))

        config = configparser.RawConfigParser()
        config.optionxform = str
        config.read(sys.argv[2])
        keyStore = key_store.KeyStore.readStore(config)

    elif sys.argv[1] == 'json':
        if len(sys.argv) != 4:
            usage()

        with open(sys.argv[2]) as f:
            jsonStore = json.load(f)

            key = utils.loadKeyFromJson(jsonStore)
            keyStore = key_store.KeyStore.readStoreFromJson(jsonStore)

    else:
        usage()

    pool = None
    if nprocs > 1:
        import multiprocessing
        pool = multiprocessing.Pool(nprocs)

    dep = None
    with open(sys.argv[3]) as f:
        dep = json.load(f)

    state = None
    if statePassthrough:
        state = verification_state.ClusterState.readStateFromJson(
                json.load(sys.stdin))
        if continueLast:
            registerIdx = len(state.cashRegisters) - 1

    if nprocs > 1:
        try:
            pdep = parseDEPAndGroups(dep)
            state = verifyParsedDEP(pdep, keyStore, key, state, registerIdx, pool,
                    nprocs)
        finally:
            pool.terminate()
            pool.join()
    else:
        state = verifyDEP(dep, keyStore, key, state, registerIdx)

    if statePassthrough:
        print(json.dumps(
            state.writeStateToJson(), sort_keys=False, indent=2))

    print(_("Verification successful."), file=sys.stderr)
