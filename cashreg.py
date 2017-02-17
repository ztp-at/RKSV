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
This module provides classes that can act as a simple cash register.
"""
from builtins import int
from builtins import range

import base64

import algorithms
import receipt
import utils

class CashRegisterI(object):
    """
    The base class for cash registers. It contains functions that every cash
    register must implement. Do not use this directly.
    """

    registerId = None
    """
    The ID of the register.
    :return: The ID of the register as a string.
    """

    lastReceiptSig = None
    """
    The last receipt.
    :return: The last receipt as JWS String
    """

    turnoverCounter = None
    """
    The turnover counter.
    :return: The turnover counter as int.
    """

    turnoverCounterSize = None
    """
    The number of bytes used to represent the turnover counter.
    :return: The size of the turnover counter as int.
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

class CashRegister(CashRegisterI):
    """
    A concrete implementation of a simple cash register.
    """

    def __init__(self, registerId, lastReceiptSig, turnoverCounter, key,
            turnoverCounterSize=8):
        """
        Creates a new cash register with the specified data.
        :param registerId: The ID of the register as a string.
        :param lastReceiptSig: The last receipt as a JWS string or None if no
        previous receipts exist.
        :param turnoverCounter: The initial value of the turnover counter.
        :param key: The AES key to encrypt the turnover counter as a byte list.
        :param turnoverCounterSize: The number of bytes used to represent
        the turnover counter as an int. Must be between 5 and 16
        (inclusive).
        """
        if turnoverCounterSize < 5 or turnoverCounterSize > 16:
            raise Exception(_("Invalid turnover counter size."))

        self.registerId = registerId
        self.lastReceiptSig = lastReceiptSig
        self.turnoverCounter = int(turnoverCounter)
        self.turnoverCounterSize = turnoverCounterSize
        self.key = key

    def receipt(self, prefix, receiptId, dateTime, sumA, sumB, sumC, sumD, sumE, sigSystem, dummy=False, reversal=False, override=dict()):
        algorithm = algorithms.ALGORITHMS[prefix]

        certSerial = override.get('certSerial', sigSystem.serial)
        zda = override.get('zda', sigSystem.zda)

        registerId = override.get('registerId', self.registerId)

        rec = receipt.Receipt(zda, registerId, receiptId, dateTime,
            sumA, sumB, sumC, sumD, sumE, '', certSerial, '')

        if 'turnoverCounterSize' in override:
            self.turnoverCounterSize = override['turnoverCounterSize']

        encTurnoverCounter = None
        if dummy:
            encTurnoverCounter = b'TRA'

            if 'turnoverCounter' in override:
                self.turnoverCounter = int(override['turnoverCounter'])
        else:
            # TODO: check if counter can still be represented with
            # given size
            self.turnoverCounter += int(round((sumA + sumB + sumC + sumD + sumE) * 100))
            if 'turnoverCounter' in override:
                self.turnoverCounter = int(override['turnoverCounter'])

            if reversal:
                encTurnoverCounter = b'STO'
            else:
                if not algorithm.verifyKey(self.key):
                    raise Exception(_("Invalid key."))
                encTurnoverCounter = algorithm.encryptTurnoverCounter(rec,
                        self.turnoverCounter, self.key,
                        self.turnoverCounterSize)
        encTurnoverCounter = base64.b64encode(encTurnoverCounter)
        encTurnoverCounter = encTurnoverCounter.decode("utf-8")
        rec.encTurnoverCounter = encTurnoverCounter

        previousChain = algorithm.chain(rec, self.lastReceiptSig)
        rec.previousChain = base64.b64encode(previousChain).decode("utf-8")
        if 'previousChain' in override:
            rec.previousChain = override['previousChain']

        prefix = override.get('algorithmPrefix', prefix)
        jwsString = sigSystem.sign(rec.toPayloadString(prefix),
                algorithm)
        self.lastReceiptSig = jwsString
        
        header, payload, signature = jwsString.split('.')
        header = base64.urlsafe_b64decode(
                utils.restoreb64padding(header).encode('utf-8')
                ).decode('utf-8')
        if 'header' in override:
            header = override['header']
        if 'signature' in override:
            signature = override['signature']

        rec.sign(header, signature)

        return rec
