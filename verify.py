#!/usr/bin/python3

import base64
import jwt

import rechnung
import utils

class ReceiptVerifierI:
    def verify(self, receipt, previous):
        raise NotImplementedError("Please implement this yourself.")

class DEPException(Exception):
    pass

class UnknownAlgorithmException(rechnung.ReceiptException):
    def __init__(self, receipt):
        super(UnknownAlgorithmException, self).__init__(receipt, "Unknown algorithm.")

class ChainingException(DEPException):
    def __init__(self, receipt, receiptPrev):
        super(ChainingException, self).__init__("At receipt \"" + receipt
                + "\": Previous receipt is not \"" + receiptPrev + "\".")

class NoRestoreReceiptAfterSignatureSystemFailureException(DEPException):
    def __init__(self, receipt):
        super(NoRestoreReceiptAfterSignatureSystemFailureException, self).__init__("At receipt \"" + receipt
                + "\": Receipt after restored signature system must not have any turnover.")

class CertSerialMismatchException(rechnung.ReceiptException):
    def __init__(self, receipt):
        super(CertSerialMismatchException, self).__init__(receipt, "Certificate serial mismatch.")

class InvalidSignatureException(rechnung.ReceiptException):
    def __init__(self, receipt):
        super(InvalidSignatureException, self).__init__(receipt, "Invalid Signature.")

class SignatureSystemFailedException(rechnung.ReceiptException):
    def __init__(self, receipt):
        super(SignatureSystemFailedException, self).__init__(receipt, "Signature System failed.")

class InvalidTurnoverCounterException(rechnung.ReceiptException):
    def __init__(self, receipt):
        super(InvalidTurnoverCounterException, self).__init__(receipt, "Turnover counter invalid.")

def depCert2PEM(depCert):
    return '-----BEGIN CERTIFICATE-----\n' + depCert +  '\n-----END CERTIFICATE-----'

def depCert2pubKey(depCert):
    pemCert = depCert2PEM(depCert)
    pubKey = utils.loadCert(pemCert).public_key()
    return pubKey

def restoreb64padding(data):
    needed = 4 - len(data) % 4
    if needed:
        data += '=' * needed
    return data

class ReceiptVerifier(ReceiptVerifierI):
    def __init__(self, cert):
        self.cert = cert

    def verifyJWS(self, jwsString):
        validationSuccessful = False
        try:
            jwt.PyJWS().decode(jwsString, depCert2pubKey(self.cert))
            validationSuccessful = True
        except jwt.exceptions.DecodeError as e:
            pass

        receipt, algorithmPrefix = rechnung.Rechnung.fromJWSString(jwsString)

        if 'R1-AT0' != algorithmPrefix: # Only support this one algoritm for now.
            raise UnknownAlgorithmException(jwsString)

        serial = utils.loadCert(depCert2PEM(self.cert)).serial
        serial = ("%d" % serial)
        # for some reason the ref impl has a negative serial on some certs
        if serial != receipt.certSerial and ('-' + serial) != receipt.certSerial:
            raise CertSerialMismatchException(jwsString)

        if not validationSuccessful:
            if receipt.isSignedBroken():
                raise SignatureSystemFailedException(jwsString)
            else:
                raise InvalidSignatureException(jwsString)

        return receipt

def verifyChain(receipt, prev):
    chainingValue = None
    if prev:
        chainingValue = utils.sha256(prev.encode("utf-8"))
    else:
        chainingValue = utils.sha256(receipt.registerId.encode("utf-8"))
    chainingValue = base64.b64encode(chainingValue[0:8])
    if chainingValue.decode("utf-8") != receipt.previousChain:
        raise ChainingException(receipt, prev)

def verifyCert(cert, chain):
    # TODO
    pass

def verifyGroup(group, lastReceipt, lastTurnoverCounter, key):
    cert = group['Signaturzertifikat']

    chain = group['Zertifizierungsstellen']
    verifyCert(cert, chain)

    rv = ReceiptVerifier(cert)
    prev = lastReceipt
    prevObj = None
    if prev:
        prevObj, algorithmPrefix = rechnung.Rechnung.fromJWSString(prev)
    for r in group['Belege-kompakt']:
        ro = None
        try:
            ro = rv.verifyJWS(r)
            if not prevObj or prevObj.isSignedBroken():
                if ro.sumA != 0.0 or ro.sumB != 0.0 or ro.sumC != 0.0 or ro.sumD != 0.0 or ro.sumE != 0.0:
                    raise NoRestoreReceiptAfterSignatureSystemFailureException(r)
        except SignatureSystemFailedException as e:
            ro, algorithmPrefix = rechnung.Rechnung.fromJWSString(r)

        if not ro.isDummy():
            if key:
                newC = lastTurnoverCounter + int(round((ro.sumA + ro.sumB + ro.sumC + ro.sumD + ro.sumE) * 100))
                if not ro.isReversal():
                    turnoverCounter = ro.decryptTurnoverCounter(key)
                    if turnoverCounter != newC:
                        print(newC)
                        print(turnoverCounter)
                        raise InvalidTurnoverCounterException(r)
                lastTurnoverCounter = newC

        verifyChain(ro, prev)

        prev = r
        prevObj = ro

    return prev, lastTurnoverCounter

def verifyDEP(dep, key):
    lastReceipt = None
    lastTurnoverCounter = 0
    for group in dep['Belege-Gruppe']:
        lastReceipt, lastTurnoverCounter = verifyGroup(group, lastReceipt, lastTurnoverCounter, key)

import json
import sys

if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: ./demo.py <dep export file> <base64 AES key file>")
        sys.exit(0)

    key = None
    if len(sys.argv) == 3:
        with open(sys.argv[2]) as f:
            key = base64.b64decode(f.read().encode("utf-8"))

    with open(sys.argv[1]) as f:
        verifyDEP(json.loads(f.read()), key)
