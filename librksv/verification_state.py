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
This module contains classes for a verification state that is returned by a
verifcation function and can be fed to a subsequent call.
"""
from builtins import int
from builtins import range

from .gettext_helper import _

from six import string_types

import base64
import copy

from . import algorithms
from . import depparser
from . import receipt
from . import utils

class StateException(utils.RKSVException):
    def __init__(self, message):
        super(StateException, self).__init__(message)
        self._initargs = (message,)

    def __reduce__(self):
        return (self.__class__, self._initargs)

class InvalidCashRegisterIndexException(StateException):
    def __init__(self, idx):
        super(InvalidCashRegisterIndexException, self).__init__(
                _("No cash register with index {}.").format(idx))
        self._initargs = (idx,)

class NoStartReceiptForLastCashRegisterException(StateException):
    def __init__(self):
        super(NoStartReceiptForLastCashRegisterException,
                self).__init__(_("The last cash register has no registered start receipt."))
        self._initargs = ()

class StateParseException(StateException):
    """
    Indicates that an error occurred while parsing the state.
    """

    def __init__(self, msg):
        super(StateParseException, self).__init__(msg)
        self._initargs = (msg,)

class MalformedStateException(StateParseException):
    """
    Indicates that the state is not properly formed.
    """

    def __init__(self, msg=None, regidx=None):
        if msg is None:
            super(MalformedStateException, self).__init__(
                    _("Malformed verification state"))
        else:
            if regidx is None:
                super(MalformedStateException, self).__init__(
                        _('{}.').format(msg))
            else:
                super(MalformedStateException, self).__init__(
                        _("In cash register {}: {}.").format(regidx, msg))
        self._initargs = (msg, regidx)

class MissingStateElementException(MalformedStateException):
    """
    Indicates that an element in the state is missing.
    """

    def __init__(self, elem, regidx=None):
        super(MissingStateElementException, self).__init__(
                _("Element \"{}\" missing").format(elem),
                regidx)
        self._initargs = (elem, regidx)

class MalformedStateElementException(MalformedStateException):
    """
    Indicates that an element in the state is malformed.
    """

    def __init__(self, elem, detail=None, regidx=None):
        if detail is None:
            super(MalformedStateElementException, self).__init__(
                    _("Element \"{}\" malformed").format(elem),
                    regidx)
        else:
            super(MalformedStateElementException, self).__init__(
                    _("Element \"{}\" malformed: {}").format(elem, detail),
                    regidx)
        self._initargs = (elem, detail, regidx)

class CashRegisterState(object):
    """
    An object holding the state of a cash register. This allows for the
    verification of partial DEPs.
    """

    def __init__(self):
        self.startReceiptJWS = None
        self.lastReceiptJWS = None
        self.lastTurnoverCounter = 0
        self.needRestoreReceipt = False

    @staticmethod
    def fromDict(d, regidx = None):
        if 'startReceiptJWS' not in d:
            raise MissingStateElementException('startReceiptJWS', regidx)
        if 'lastReceiptJWS' not in d:
            raise MissingStateElementException('lastReceiptJWS', regidx)
        if 'lastTurnoverCounter' not in d:
            raise MissingStateElementException('lastTurnoverCounter', regidx)
        if 'needRestoreReceipt' not in d:
            raise MissingStateElementException('needRestoreReceipt', regidx)

        ret = CashRegisterState()

        ret.startReceiptJWS = d['startReceiptJWS']
        if not ret.startReceiptJWS is None and not isinstance(
                ret.startReceiptJWS, string_types):
            raise MalformedStateElementException('startReceiptJWS',
                    _('not a string'), regidx)

        ret.lastReceiptJWS = d['lastReceiptJWS']
        if not ret.lastReceiptJWS is None and not isinstance(
                ret.lastReceiptJWS, string_types):
            raise MalformedStateElementException('lastReceiptJWS',
                    _('not a string'), regidx)

        ret.lastTurnoverCounter = d['lastTurnoverCounter']
        if not isinstance(ret.lastTurnoverCounter, int):
            raise MalformedStateElementException('lastTurnoverCounter',
                    _('not an integer'), regidx)

        ret.needRestoreReceipt = d['needRestoreReceipt']
        if not isinstance(ret.needRestoreReceipt, bool):
            raise MalformedStateElementException('needRestoreReceipt',
                    _('not a boolean'), regidx)

        return ret

    @staticmethod
    def fromDEPGroup(old, group, key = None):
        new = copy.copy(old)
        new.updateFromDEPGroup(group, key)
        return new

    def updateFromDEPGroup(self, group, key = None):
        if len(group) <= 0:
            return

        if len(group) == 1:
            secondToLastReceiptJWS = self.lastReceiptJWS
        else:
            secondToLastReceiptJWS = depparser.expandDEPReceipt(group[-2])

        stl = None
        if secondToLastReceiptJWS:
            stl, prefix = receipt.Receipt.fromJWSString(secondToLastReceiptJWS)
        last, prefix = receipt.Receipt.fromJWSString(
                depparser.expandDEPReceipt(group[-1]))

        if not last.isSignedBroken() and stl and (not last.isNull() or
                last.isDummy() or last.isReversal()) and stl.isSignedBroken():
            self.needRestoreReceipt = True
        else:
            self.needRestoreReceipt = False

        if not self.startReceiptJWS:
            self.startReceiptJWS = depparser.expandDEPReceipt(group[0])

        self.lastReceiptJWS = depparser.expandDEPReceipt(group[-1])

        if not key:
            return

        reversals = list()
        for i in range(len(group) - 1, -1, -1):
            ro, prefix = receipt.Receipt.fromJWSString(
                depparser.expandDEPReceipt(group[i]))
            if (not ro.isDummy()) and (not ro.isReversal()):
                alg = algorithms.ALGORITHMS[prefix]
                self.lastTurnoverCounter = ro.decryptTurnoverCounter(key, alg)
                break
            if ro.isReversal():
                reversals.insert(0, ro)

        for ro in reversals:
            self.lastTurnoverCounter += int(round(
                (ro.sumA + ro.sumB + ro.sumC + ro.sumD + ro.sumE) * 100))

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        return NotImplemented

    def __ne__(self, other):
        if isinstance(other, self.__class__):
            return not self.__eq__(other)
        return NotImplemented

class ClusterState(object):
    """
    An object holding the state of a GGS cluster. It keeps a list of
    CashRegisterState objects and a set of used receipt IDs. For a register
    that is not in a GGS use a ClusterState with a single cash register.
    """

    def __init__(self, initReceiptJWS = None, initUsedReceiptIds = None):
        self.cashRegisters = list()
        self.usedReceiptIds = set()

        if initReceiptJWS:
            self.addNewCashRegister()
            self.cashRegisters[0].startReceiptJWS = initReceiptJWS

        if initUsedReceiptIds:
            self.usedReceiptIds.update(initUsedReceiptIds)

    def addNewCashRegister(self):
        """
        Appends a new cash register to the list of cash registers. If the
        current last cash register does not have a start receipt, this
        operation fails with an exception.
        :throws: NoStartReceiptForLastCashRegisterException
        """
        if (len(self.cashRegisters) > 0 and not
                self.cashRegisters[-1].startReceiptJWS):
            raise NoStartReceiptForLastCashRegisterException()

        self.cashRegisters.append(CashRegisterState())

    def getCashRegisterInfo(self, registerIdx):
        """
        Retrieves the requested cash register state, the previous cash
        register's start receipt and the used receipt IDs from the cluster
        state. This info is needed to verify a new DEP.
        :param registerIdx: The index of the cash register or None if a new
        one should be added.
        :return: The start receipt of the previous cash register in JWS
        format or None, if registerIdx equals zero, a copy of the state
        of the specified cash register as CashRegisterState object and a
        copy of the set of used receipt IDs.
        :throws InvalidCashRegisterIndexException
        """
        if registerIdx is None or registerIdx == len(self.cashRegisters):
            registerIdx = len(self.cashRegisters)
            self.addNewCashRegister()
        if registerIdx < 0 or registerIdx > len(self.cashRegisters):
            raise InvalidCashRegisterIndexException(registerIdx)

        prev = None
        if registerIdx > 0:
            prev = self.cashRegisters[registerIdx - 1].startReceiptJWS

        return prev, copy.copy(
                self.cashRegisters[registerIdx]), copy.copy(
                        self.usedReceiptIds)

    def updateCashRegisterInfo(self, registerIdx, newRegisterState,
            newUsedReceiptIds):
        """
        Updates the cluster state after a DEP by the given register has
        been verified.
        :param registerIdx: The index of the cash register or None if the
        last one should be updated.
        :param newRegisterState: The updated state of the cash register as
        a CashRegisterState object.
        :param newUsedReceiptIds: The updated set of used receipt IDs.
        :throws InvalidCashRegisterIndexException
        """
        if registerIdx is None:
            registerIdx = len(self.cashRegisters) - 1
        elif registerIdx < 0 or registerIdx >= len(self.cashRegisters):
            raise InvalidCashRegisterIndexException(registerIdx)

        self.cashRegisters[registerIdx] = newRegisterState
        self.usedReceiptIds.update(newUsedReceiptIds)

    @staticmethod
    def readStateFromJson(json):
        if not isinstance(json, dict):
            raise MalformedStateException(_('Malformed verification state root'))

        if 'cashRegisters' not in json:
            raise MissingStateElementException('cashRegisters')
        if 'usedReceiptIds' not in json:
            raise MissingStateElementException('usedReceiptIds')

        cregs = json['cashRegisters']
        if not isinstance(cregs, list):
            raise MalformedStateElementException('cashRegisters', _('not a list'))

        recids = json['usedReceiptIds']
        if not isinstance(recids, list):
            raise MalformedStateElementException('usedReceiptIds', _('not a list'))

        ret = ClusterState()

        for i in range(0, len(cregs)):
            if not isinstance(cregs[i], dict):
                raise MalformedStateElementException('cashRegisters',
                        _('not an object'), i)

            cro = CashRegisterState.fromDict(cregs[i], i)
            ret.cashRegisters.append(cro)

        for recid in recids:
            if not isinstance(recid, string_types):
                raise MalformedStateElementException('usedReceiptIds',
                        _('receipt ID not a string'))

        ret.usedReceiptIds = set(recids)

        return ret

    def writeStateToJson(self):
        regs = list()
        for cr in self.cashRegisters:
            regs.append(copy.copy(cr.__dict__))

        return {
                'cashRegisters': regs,
                'usedReceiptIds': list(self.usedReceiptIds)
        }
