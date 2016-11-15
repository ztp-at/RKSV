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
        return ret

    def writeStateToJson(self):
        return copy.deepcopy(self.__dict__)
