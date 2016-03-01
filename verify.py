#!/usr/bin/python3

"""
This module provides functions to verify a DEP.
"""
import base64

import algorithms
import rechnung
import utils
import verify_receipt

class DEPException(Exception):
    """
    An exception that is thrown if something is wrong with a DEP.
    """

    pass

class ChainingException(DEPException):
    """
    This exception indicates that the chaining value in a receipt is invalid and
    that the chain of receipts can not be verified.
    """

    def __init__(self, receipt, receiptPrev):
        super(ChainingException, self).__init__("At receipt \"" + receipt
                + "\": Previous receipt is not \"" + receiptPrev + "\".")

class NoRestoreReceiptAfterSignatureSystemFailureException(DEPException):
    """
    This exception indicates that, after a signature system is first used or
    after it has been repaired, no receipt with zero turnover was created as
    required.
    """

    def __init__(self, receipt):
        super(NoRestoreReceiptAfterSignatureSystemFailureException, self).__init__("At receipt \"" + receipt
                + "\": Receipt after restored signature system must not have any turnover.")

class InvalidTurnoverCounterException(rechnung.ReceiptException):
    """
    This exception indicates that the turnover counter is invalid.
    """

    def __init__(self, receipt):
        super(InvalidTurnoverCounterException, self).__init__(receipt, "Turnover counter invalid.")

class NoCertificateGivenException(DEPException):
    """
    This exception indicates that a DEP using multiple receipt groups did not
    specify the used certificate for a group.
    """

    def __init__(self):
        super(NoCertificateGivenException, self).__init__("No certificate specified in DEP and multiple groups used.")

class UntrustedCertificateException(DEPException):
    """
    This exception indicates that neither the used certificate (or public key)
    nor any of the certificates in the certificate chain is available in the
    used key store.
    """

    def __init__(self, cert):
        super(UntrustedCertificateException, self).__init__("Certificate \"" + cert + "\" is not trusted.")

class SignatureSystemFailedOnInitialReceiptException(rechnung.ReceiptException):
    """
    Indicates that the initial receipt was not signed.
    """
    def __init__(self, receipt):
        super(SignatureSystemFailedOnInitialReceiptException, self).__init__(receipt, "Initial receipt not signed.")

def verifyChain(receipt, prev, algorithm):
    """
    Verifies that a receipt is preceeded by another receipt in the receipt
    chain. It returns nothing on success and throws an exception otherwise.
    :param receipt: The new receipt as a receipt object.
    :param prev: The previous receipt as a JWS string.
    :param algorithm: The algorithm class to use.
    :throws: ChainingException
    """
    chainingValue = algorithm.chain(receipt, prev)
    chainingValue = base64.b64encode(chainingValue)
    if chainingValue.decode("utf-8") != receipt.previousChain:
        raise ChainingException(receipt, prev)

def verifyCert(cert, chain, keyStore):
    """
    Verifies that a certificate or one of its signers is in the given key store.
    Returns nothing on success and throws an exception otherwise.
    :param cert: The certificate to verify as a PEM string without header and
    footer.
    :param chain: A list of certificates as PEM strings without header and
    footer. These represent the signing chain for the certificate.
    :param keyStore: The key store.
    :throws: UntrustedCertificateException
    """
    prev = utils.loadCert(utils.addPEMCertHeaders(cert))

    for c in chain:
        if keyStore.getKey(key_store.preprocCertSerial("%d" % prev.serial)):
            return

        cur = utils.loadCert(utils.addPEMCertHeaders(c))

        if not utils.verifyCert(prev, cur):
            raise UntrustedCertificateException(cert)

        prev = cur

    if keyStore.getKey(key_store.preprocCertSerial("%d" % prev.serial)):
        return

    raise UntrustedCertificateException(cert)

def verifyGroup(group, lastReceipt, rv, lastTurnoverCounter, key):
    """
    Verifies a group of receipts from a DEP. It checks if the signature of each
    receipt is valid, if the receipts are properly chained and if receipts with
    zero turnover are present as required. If a key is specified it also
    verifies the turnover counter. Returns the last receipt in the group and the
    last known value of the turnover counter on success and throws an exception
    otherwise.
    :param group: The receipt group as a json object.
    :param lastReceipt: The last receipt from the previous group (if any) as JWS
    string.
    :param rv: The receipt verifier object used to verify single receipts.
    :param lastTurnoverCounter: The last known value of the turnover counter as
    int.
    :param key: The key used to decrypt the turnover counter as a byte list or
    None.
    :return: The last receipt in the group as JWS string and the last known
    value of the turnover counter as int.
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
    """
    prev = lastReceipt
    prevObj = None
    if prev:
        prevObj, algorithmPrefix = rechnung.Rechnung.fromJWSString(prev)
    for r in group['Belege-kompakt']:
        ro = None
        algorithm = None
        try:
            ro, algorithm = rv.verifyJWS(r)
            if not prevObj or prevObj.isSignedBroken():
                if ro.sumA != 0.0 or ro.sumB != 0.0 or ro.sumC != 0.0 or ro.sumD != 0.0 or ro.sumE != 0.0:
                    raise NoRestoreReceiptAfterSignatureSystemFailureException(r)
        except verify_receipt.SignatureSystemFailedException as e:
            if not prevObj:
                raise SignatureSystemFailedOnInitialReceiptException(r)
            ro, algorithmPrefix = rechnung.Rechnung.fromJWSString(r)
            algorithm = algorithms.ALGORITHMS[algorithmPrefix]

        if not ro.isDummy():
            if key:
                newC = lastTurnoverCounter + int(round((ro.sumA + ro.sumB + ro.sumC + ro.sumD + ro.sumE) * 100))
                if not ro.isReversal():
                    turnoverCounter = ro.decryptTurnoverCounter(key, algorithm)
                    if turnoverCounter != newC:
                        raise InvalidTurnoverCounterException(r)
                lastTurnoverCounter = newC

        verifyChain(ro, prev, algorithm)

        prev = r
        prevObj = ro

    return prev, lastTurnoverCounter

def verifyDEP(dep, keyStore, key):
    """
    Verifies an entire DEP. It checks if the signature of each receipt is valid,
    if the receipts are properly chained, if receipts with zero turnover are
    present as required and if the certificates used to sign the receipts are
    valid. If a key is specified it also verifies the turnover counter. Returns
    nothing on success and throws an exception otherwise.
    :param dep: The DEP as a json object.
    :param keyStore: The key store object containing the used public keys and
    certificates.
    :param key: The key used to decrypt the turnover counter as a byte list or
    None.
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
    :throws: SignatureSystemFailedOnInitialReceiptException
    """
    lastReceipt = None
    lastTurnoverCounter = 0

    if len(dep['Belege-Gruppe']) == 1 and not dep['Belege-Gruppe'][0]['Signaturzertifikat']:
        rv = verify_receipt.ReceiptVerifier.fromKeyStore(keyStore)
        lastReceipt, lastTurnoverCounter = verifyGroup(
                dep['Belege-Gruppe'][0], lastReceipt,
                rv, lastTurnoverCounter, key)
        return

    for group in dep['Belege-Gruppe']:
        cert = group['Signaturzertifikat']
        if not cert:
            raise NoCertificateGivenException()

        chain = group['Zertifizierungsstellen']
        verifyCert(cert, chain, keyStore)
        rv = verify_receipt.ReceiptVerifier.fromDEPCert(cert)
    
        lastReceipt, lastTurnoverCounter = verifyGroup(group, lastReceipt,
                rv, lastTurnoverCounter, key)

import configparser
import json
import sys

import key_store

if __name__ == "__main__":
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Usage: ./verify.py <key store> <dep export file> [<base64 AES key file>]")
        sys.exit(0)

    key = None
    if len(sys.argv) == 4:
        with open(sys.argv[3]) as f:
            key = base64.b64decode(f.read().encode("utf-8"))

    with open(sys.argv[2]) as f:
        config = configparser.RawConfigParser()
        config.optionxform = str
        config.read(sys.argv[1])
        keyStore = key_store.KeyStore.readStore(config)

        verifyDEP(json.loads(f.read()), keyStore, key)
