import base64
import struct

import algorithms
import rechnung

class RegistrierkassaI:
    def receipt(self, datetime, sumA, sumB, sumC, sumD, sumE, sigSystem):
        raise NotImplementedError("Please implement this yourself.")

    def registerId(self):
        raise NotImplementedError("Please implement this yourself.")

    def lastReceiptSig(self):
        raise NotImplementedError("Please implement this yourself.")

    def turnoverCounter(self):
        raise NotImplementedError("Please implement this yourself.")

class Registrierkassa(RegistrierkassaI):
    def __init__(self, zda, registerId, lastReceiptSig, turnoverCounter, key):
        self.zda = zda
        self.registerId = registerId
        self.lastReceiptSig = lastReceiptSig
        self.turnoverCounter = int(turnoverCounter)
        self.key = key

    def receipt(self, prefix, receiptId, dateTime, sumA, sumB, sumC, sumD, sumE, sigSystem, dummy=False, reversal=False):
        algorithm = algorithms.ALGORITHMS[prefix]

        certSerial = sigSystem.serial

        receipt = rechnung.Rechnung(self.zda, self.registerId, receiptId, dateTime,
            sumA, sumB, sumC, sumD, sumE, '', certSerial, '')

        encTurnoverCounter = None
        if dummy:
            encTurnoverCounter = b'TRA'
        else:
            self.turnoverCounter += int(round((sumA + sumB + sumC + sumD + sumE) * 100))
            if reversal:
                encTurnoverCounter = b'STO'
            else:
                encTurnoverCounter = algorithm.encryptTurnoverCounter(receipt,
                        self.turnoverCounter, self.key)
        encTurnoverCounter = base64.b64encode(encTurnoverCounter)
        encTurnoverCounter = encTurnoverCounter.decode("utf-8")
        receipt.encTurnoverCounter = encTurnoverCounter

        previousChain = algorithm.chain(receipt, self.lastReceiptSig)
        receipt.previousChain = base64.b64encode(previousChain).decode("utf-8")

        jwsString = sigSystem.sign(receipt.toPayloadString(prefix).encode("utf-8"),
                algorithm)
        self.lastReceiptSig = jwsString.decode("utf-8")

        return self.lastReceiptSig

    def registerId(self):
        return self.registerId

    def lastReceiptSig(self):
        return self.lastReceiptSig

    def turnoverCounter(self):
        return self.turnoverCounter
