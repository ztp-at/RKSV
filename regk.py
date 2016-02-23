import base64
import struct

import rechnung
import utils

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

    def receipt(self, receiptId, dateTime, sumA, sumB, sumC, sumD, sumE, sigSystem, dummy=False, reversal=False):
        prefix = "R1" # static for now

        encTurnoverCounter = None
        if dummy:
            encTurnoverCounter = b'TRA'
        else:
            self.turnoverCounter += int(round((sumA + sumB + sumC + sumD + sumE) * 100))
            if reversal:
                encTurnoverCounter = b'STO'
            else:
                iv = utils.sha256(self.registerId.encode("utf-8") + receiptId.encode("utf-8"))[0:16]
                # for now 8 byte counter
                pt = struct.pack(">q", self.turnoverCounter)
                encTurnoverCounter = utils.aes256ctr(iv, self.key, pt)
        encTurnoverCounter = base64.b64encode(encTurnoverCounter)
        encTurnoverCounter = encTurnoverCounter.decode("utf-8")

        certSerial = sigSystem.serial

        previousChain = None
        if self.lastReceiptSig:
            previousChain = utils.sha256(self.lastReceiptSig)
        else:
            previousChain = utils.sha256(self.registerId.encode("utf-8"))
        previousChain = base64.b64encode(previousChain[0:8]).decode("utf-8")

        receipt = rechnung.Rechnung(self.zda, self.registerId, receiptId, dateTime,
            sumA, sumB, sumC, sumD, sumE, encTurnoverCounter,
            certSerial, previousChain)

        jwsString = sigSystem.sign(receipt.toPayloadString(prefix).encode("utf-8"))
        self.lastReceiptSig = jwsString

        return jwsString.decode("utf-8")

    def registerId(self):
        return self.registerId

    def lastReceiptSig(self):
        return self.lastReceiptSig

    def turnoverCounter(self):
        return self.turnoverCounter
