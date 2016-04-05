"""
This module provides classes that can act as a simple cash register.
"""
import base64

import algorithms
import receipt

class CashRegisterI:
    """
    The base class for cash registers. It contains functions that every cash
    register must implement. Do not use this directly.
    """

    def receipt(self, prefix, receiptId, dateTime, sumA, sumB, sumC, sumD, sumE,
            sigSystem, dummy=False, reversal=False):
        """
        Generates a new receipt with the given parameters and the data stored in
        the cash register and lets the given signature system sign it.
        :param prefix: The ID of the algorithm class to use as a string.
        :param receiptId: The ID of the receipt as a string.
        :param dateTime: The receipt's timestamp as a datetime object.
        :param sumA: The first sum as a float.
        :param sumB: The second sum as a float.
        :param sumC: The third sum as a float.
        :param sumD: The fourth sum as a float.
        :param sumE: The fifth sum as a float.
        :param sigSystem: The signature system to use.
        :param dummy: Whether the generated receipt is a dummy receipt.
        :param reversal: Whether the generated receipt is a reversal.
        :return: The created receipt as a receipt object.
        """
        raise NotImplementedError("Please implement this yourself.")

    def registerId(self):
        """
        The ID of the register.
        :return: The ID of the register as a string.
        """
        raise NotImplementedError("Please implement this yourself.")

    def lastReceiptSig(self):
        """
        The last receipt.
        :return: The last receipt as JWS String
        """
        raise NotImplementedError("Please implement this yourself.")

    def turnoverCounter(self):
        """
        The turnover counter.
        :return: The turnover counter as int.
        """
        raise NotImplementedError("Please implement this yourself.")

class CashRegister(CashRegisterI):
    """
    A concrete implementation of a simple cash register.
    """

    def __init__(self, registerId, lastReceiptSig, turnoverCounter, key):
        """
        Creates a new cash register with the specified data.
        :param registerId: The ID of the register as a string.
        :param lastReceiptSig: The last receipt as a JWS string or None if no
        previous receipts exist.
        :param turnoverCounter: The initial value of the turnover counter.
        :param key: The AES key to encrypt the turnover counter as a byte list.
        """
        self.registerId = registerId
        self.lastReceiptSig = lastReceiptSig
        self.turnoverCounter = int(turnoverCounter)
        self.key = key

    def receipt(self, prefix, receiptId, dateTime, sumA, sumB, sumC, sumD, sumE, sigSystem, dummy=False, reversal=False):
        algorithm = algorithms.ALGORITHMS[prefix]

        certSerial = sigSystem.serial
        zda = sigSystem.zda

        rec = receipt.Receipt(zda, self.registerId, receiptId, dateTime,
            sumA, sumB, sumC, sumD, sumE, '', certSerial, '')

        encTurnoverCounter = None
        if dummy:
            encTurnoverCounter = b'TRA'
        else:
            self.turnoverCounter += int(round((sumA + sumB + sumC + sumD + sumE) * 100))
            if reversal:
                encTurnoverCounter = b'STO'
            else:
                encTurnoverCounter = algorithm.encryptTurnoverCounter(rec,
                        self.turnoverCounter, self.key)
        encTurnoverCounter = base64.b64encode(encTurnoverCounter)
        encTurnoverCounter = encTurnoverCounter.decode("utf-8")
        rec.encTurnoverCounter = encTurnoverCounter

        previousChain = algorithm.chain(rec, self.lastReceiptSig)
        rec.previousChain = base64.b64encode(previousChain).decode("utf-8")

        jwsString = sigSystem.sign(rec.toPayloadString(prefix),
                algorithm)
        self.lastReceiptSig = jwsString
        
        header, payload, signature = jwsString.split('.')
        header = base64.urlsafe_b64decode(
                receipt.restoreb64padding(header)).decode('utf-8')
        rec.sign(header, signature)

        return rec

    def registerId(self):
        return self.registerId

    def lastReceiptSig(self):
        return self.lastReceiptSig

    def turnoverCounter(self):
        return self.turnoverCounter
