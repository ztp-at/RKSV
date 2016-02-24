#!/usr/bin/python3

import base64

import algorithms
import rechnung
import verify_receipt

class DEPException(Exception):
    pass

class ChainingException(DEPException):
    def __init__(self, receipt, receiptPrev):
        super(ChainingException, self).__init__("At receipt \"" + receipt
                + "\": Previous receipt is not \"" + receiptPrev + "\".")

class NoRestoreReceiptAfterSignatureSystemFailureException(DEPException):
    def __init__(self, receipt):
        super(NoRestoreReceiptAfterSignatureSystemFailureException, self).__init__("At receipt \"" + receipt
                + "\": Receipt after restored signature system must not have any turnover.")

class InvalidTurnoverCounterException(rechnung.ReceiptException):
    def __init__(self, receipt):
        super(InvalidTurnoverCounterException, self).__init__(receipt, "Turnover counter invalid.")

def verifyChain(receipt, prev, algorithm):
    chainingValue = algorithm.chain(receipt, prev)
    chainingValue = base64.b64encode(chainingValue)
    if chainingValue.decode("utf-8") != receipt.previousChain:
        raise ChainingException(receipt, prev)

def verifyCert(cert, chain):
    # TODO
    pass

def verifyGroup(group, lastReceipt, lastTurnoverCounter, key):
    cert = group['Signaturzertifikat']

    chain = group['Zertifizierungsstellen']
    verifyCert(cert, chain)

    rv = verify_receipt.ReceiptVerifier(cert)
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
            ro, algorithmPrefix = rechnung.Rechnung.fromJWSString(r)
            algorithm = algorithms.ALGORITHMS[algorithmPrefix]

        if not ro.isDummy():
            if key:
                newC = lastTurnoverCounter + int(round((ro.sumA + ro.sumB + ro.sumC + ro.sumD + ro.sumE) * 100))
                if not ro.isReversal():
                    turnoverCounter = ro.decryptTurnoverCounter(key, algorithm)
                    if turnoverCounter != newC:
                        print(newC)
                        print(turnoverCounter)
                        raise InvalidTurnoverCounterException(r)
                lastTurnoverCounter = newC

        verifyChain(ro, prev, algorithm)

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
