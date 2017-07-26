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
This module contains classes for a verification state that is returned by a
verifcation function and can be fed to a subsequent call.
"""
from builtins import int
from builtins import range

import base64
import copy

import algorithms
import depparser
import receipt
import utils

class StateException(Exception):
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

def printStateField(name, value):
    print('{: >25}: {}'.format(name, value))

def printCashRegisterState(state):
    printStateField(_('Start Receipt'), state.startReceiptJWS)
    printStateField(_('Last Receipt'), state.lastReceiptJWS)
    printStateField(_('Last Turnover Counter'), state.lastTurnoverCounter)
    printStateField(_('Need Restore Receipt'), state.needRestoreReceipt)

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
        ret = ClusterState()

        for cr in json['cashRegisters']:
            cro = CashRegisterState()
            cro.__dict__.update(cr)
            ret.cashRegisters.append(cro)

        ret.usedReceiptIds = set(json['usedReceiptIds'])

        return ret

    def writeStateToJson(self):
        regs = list()
        for cr in self.cashRegisters:
            regs.append(copy.copy(cr.__dict__))

        return {
                'cashRegisters': regs,
                'usedReceiptIds': list(self.usedReceiptIds)
        }

def printClusterState(state):
    for i in range(len(state.cashRegisters)):
        print(_('Cash Register {}:').format(i))
        printCashRegisterState(state.cashRegisters[i])
        print('')
    printStateField(_('Used Receipt IDs'), len(state.usedReceiptIds))

def usage():
    print("Usage: ./verification_state.py <state> create")
    print("       ./verification_state.py <state> show")
    print("       ./verification_state.py <state> addCashRegister")
    print("       ./verification_state.py <state> resetCashRegister <n>")
    print("       ./verification_state.py <state> deleteCashRegister <n>")
    print("       ./verification_state.py <state> copyCashRegister <n-Target> <source state file> <n-Source>")
    print("       ./verification_state.py <state> updateCashRegister <n-Target> <dep export file> [<base64 AES key file>]")
    print("       ./verification_state.py <state> setLastReceiptJWS <n> <receipt in JWS format>")
    print("       ./verification_state.py <state> setLastTurnoverCounter <n> <counter in cents>")
    print("       ./verification_state.py <state> toggleNeedRestoreReceipt <n>")
    print("       ./verification_state.py <state> setStartReceiptJWS <n> <receipt in JWS format>")
    print("       ./verification_state.py <state> readUsedReceiptIds <file with one receipt ID per line>")
    sys.exit(0)

if __name__ == "__main__":
    import gettext
    gettext.install('rktool', './lang', True)

    import json
    import sys

    def load_state(filename):
        with open(filename, 'r') as f:
            stateJson = utils.readJsonStream(f)
            return ClusterState.readStateFromJson(stateJson)

    def arg_str_or_none(arg):
        if arg == 'None':
            return None
        return arg

    def arg_list_from_file_or_empty(arg):
        if arg == 'None':
            return list()
        with open(arg, 'r') as f:
            return [l.strip() for l in f.readlines()]

    if len(sys.argv) < 3:
        usage()

    filename = sys.argv[1]
    state = None

    if sys.argv[2] == 'create':
        if len(sys.argv) != 3:
            usage()

        state = ClusterState()

    elif sys.argv[2] == 'show':
        if len(sys.argv) != 3:
            usage()

        state = load_state(filename)

        printClusterState(state)

    elif sys.argv[2] == 'addCashRegister':
        if len(sys.argv) != 3:
            usage()

        state = load_state(filename)
        state.addNewCashRegister()

    elif sys.argv[2] == 'resetCashRegister':
        if len(sys.argv) != 4:
            usage()

        state = load_state(filename)
        state.updateCashRegisterInfo(int(sys.argv[3]), CashRegisterState(),
                set())

    elif sys.argv[2] == 'deleteCashRegister':
        if len(sys.argv) != 4:
            usage()

        state = load_state(filename)
        del state.cashRegisters[int(sys.argv[3])]

    elif sys.argv[2] == 'setLastReceiptJWS':
        if len(sys.argv) != 5:
            usage()

        state = load_state(filename)
        state.cashRegisters[int(
            sys.argv[3])].lastReceiptJWS = arg_str_or_none(sys.argv[4])

    elif sys.argv[2] == 'setLastTurnoverCounter':
        if len(sys.argv) != 5:
            usage()

        state = load_state(filename)
        state.cashRegisters[int(
            sys.argv[3])].lastTurnoverCounter = int(sys.argv[4])

    elif sys.argv[2] == 'toggleNeedRestoreReceipt':
        if len(sys.argv) != 4:
            usage()

        state = load_state(filename)
        state.cashRegisters[int(
            sys.argv[3])].needRestoreReceipt = not state.cashRegisters[int(
                sys.argv[3])].needRestoreReceipt

    elif sys.argv[2] == 'setStartReceiptJWS':
        if len(sys.argv) != 5:
            usage()

        state = load_state(filename)
        state.cashRegisters[int(
            sys.argv[3])].startReceiptJWS = arg_str_or_none(sys.argv[4])

    elif sys.argv[2] == 'readUsedReceiptIds':
        if len(sys.argv) != 4:
            usage()

        state = load_state(filename)
        state.usedReceiptIds = set(
                arg_list_from_file_or_empty(sys.argv[3]))

    elif sys.argv[2] == 'copyCashRegister':
        if len(sys.argv) != 6:
            usage()

        state = load_state(filename)
        srcState = load_state(sys.argv[4])

        state.cashRegisters[int(
            sys.argv[3])] = srcState.cashRegisters[int(sys.argv[5])]

    elif sys.argv[2] == 'updateCashRegister':
        if len(sys.argv) != 5 and len(sys.argv) != 6:
            usage()

        key = None
        if len(sys.argv) == 6:
            with open(sys.argv[5]) as f:
                key = base64.b64decode(f.read().encode("utf-8"))

        state = load_state(filename)

        with open(sys.argv[4]) as f:
            parser = depparser.CertlessStreamDEPParser(f)

            for chunk in parser.parse(depparser.depParserChunkSize()):
                for recs, cert, chain in chunk:
                    state.cashRegisters[int(sys.argv[3])].updateFromDEPGroup(recs, key)

    else:
        usage()

    stateJson = state.writeStateToJson()
    with open(filename, 'w') as f:
        json.dump(stateJson, f, sort_keys=False, indent=2)
