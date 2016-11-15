#!/usr/bin/env python2.7

"""
This module contains classes for a verification state that is returned by a
verifcation function and can be fed to a subsequent call.
"""
from builtins import int

import copy

class VerificationState(object):
    def __init__(self):
        self.lastReceiptJWS = None
        self.lastTurnoverCounter = 0
        self.turnoverCounterSize = None
        self.usedReceiptIds = set()
        self.needRestoreReceipt = False
        self.startReceiptsJWS = []

    def resetForNewGGSClusterDEP(self):
        self.lastReceiptJWS = None
        self.lastTurnoverCounter = 0
        self.needRestoreReceipt = False

    @staticmethod
    def fromPreviousDEP(obj):
        return copy.deepcopy(obj)

    @staticmethod
    def readStateFromJson(json):
        ret = VerificationState()
        ret.__dict__.update(json)
        ret.usedReceiptIds = set(ret.usedReceiptIds)
        return ret

    def writeStateToJson(self):
        ret = copy.deepcopy(self.__dict__)
        ret['usedReceiptIds'] = list(ret['usedReceiptIds'])
        return ret

def printStateField(name, value):
    print('{: >25}: {}'.format(name, value))

def printVerificationState(state):
    printStateField(_('Last Receipt'), state.lastReceiptJWS)
    printStateField(_('Last Turnover Counter'), state.lastTurnoverCounter)
    printStateField(_('Turnover Counter Size'), state.turnoverCounterSize)
    printStateField(_('Need Restore Receipt'), state.needRestoreReceipt)
    for i in range(len(state.startReceiptsJWS)):
        printStateField(_('Start Receipt {}').format(i),
                state.startReceiptsJWS[i])

def usage():
    print("Usage: ./verification_state.py <state> create")
    print("       ./verification_state.py <state> show")
    print("       ./verification_state.py <state> setLastReceiptJWS <receipt in JWS format>")
    print("       ./verification_state.py <state> setLastTurnoverCounter <counter in cents>")
    print("       ./verification_state.py <state> setTurnoverCounterSize <size in bytes>")
    print("       ./verification_state.py <state> toggleNeedRestoreReceipt")
    print("       ./verification_state.py <state> readUsedReceiptIds <file with one receipt ID per line>")
    print("       ./verification_state.py <state> setStartReceiptsJWS <JWS receipt 1>...")
    print("       ./verification_state.py <state> addStartReceiptsJWS <JWS receipt>")
    print("       ./verification_state.py <state> readStartReceiptsJWS <file with one JWS receipt per line>")
    print("       ./verification_state.py <state> reset")
    print("       ./verification_state.py <state> resetForGGS")
    sys.exit(0)

if __name__ == "__main__":
    import gettext
    gettext.install('rktool', './lang', True)

    import json
    import sys

    def load_state(filename):
        with open(filename, 'r') as f:
            stateJson = json.load(f)
            return VerificationState.readStateFromJson(stateJson)

    def arg_str_or_none(arg):
        if arg == 'None':
            return None
        return arg

    def arg_int_or_none(arg):
        if arg == 'None':
            return None
        return int(arg)

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

        state = VerificationState()

    elif sys.argv[2] == 'show':
        if len(sys.argv) != 3:
            usage()

        state = load_state(filename)

        printVerificationState(state)

    elif sys.argv[2] == 'setLastReceiptJWS':
        if len(sys.argv) != 4:
            usage()

        state = load_state(filename)
        state.lastReceiptJWS = arg_str_or_none(sys.argv[3])

    elif sys.argv[2] == 'setLastTurnoverCounter':
        if len(sys.argv) != 4:
            usage()

        state = load_state(filename)
        state.lastTurnoverCounter = int(sys.argv[3])

    elif sys.argv[2] == 'setTurnoverCounterSize':
        if len(sys.argv) != 4:
            usage()

        state = load_state(filename)
        tcs = arg_int_or_none(sys.argv[3])
        if tcs is not None and (tcs < 5 or tcs > 16):
            print(_("Turnover counter size needs to be between 5 and 16."))
            sys.exit(1)
        state.turnoverCounterSize = tcs

    elif sys.argv[2] == 'toggleNeedRestoreReceipt':
        if len(sys.argv) != 3:
            usage()

        state = load_state(filename)
        state.needRestoreReceipt = not state.needRestoreReceipt

    elif sys.argv[2] == 'readUsedReceiptIds':
        if len(sys.argv) != 4:
            usage()

        state = load_state(filename)
        state.usedReceiptIds = set(
                arg_list_from_file_or_empty(sys.argv[3]))

    elif sys.argv[2] == 'setStartReceiptsJWS':
        if len(sys.argv) < 3:
            usage()

        state = load_state(filename)
        state.startReceiptsJWS = sys.argv[3:]

    elif sys.argv[2] == 'addStartReceiptsJWS':
        if len(sys.argv) != 4:
            usage()

        state = load_state(filename)
        state.startReceiptsJWS.append(sys.argv[3])

    elif sys.argv[2] == 'readStartReceiptsJWS':
        if len(sys.argv) != 4:
            usage()

        state = load_state(filename)
        state.startReceiptsJWS = arg_list_from_file_or_empty(sys.argv[3])

    elif sys.argv[2] == 'reset':
        if len(sys.argv) != 3:
            usage()

        state = VerificationState()

    elif sys.argv[2] == 'resetForGGS':
        if len(sys.argv) != 3:
            usage()

        state = load_state(filename)
        state.resetForNewGGSClusterDEP()

    else:
        usage()

    stateJson = state.writeStateToJson()
    with open(filename, 'w') as f:
        json.dump(stateJson, f, sort_keys=False, indent=2)
