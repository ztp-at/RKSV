#!/usr/bin/python3

import utils

class KeyStoreI:
    def getKey(self, keyId):
        raise NotImplementedError("Please implement this yourself.")

    def putKey(self, keyId, key):
        raise NotImplementedError("Please implement this yourself.")

    def putPEMCert(self, pemCert):
        raise NotImplementedError("Please implement this yourself.")

    def putPEMKey(self, keyId, pemKey):
        raise NotImplementedError("Please implement this yourself.")

    def writeStore(self, config):
        raise NotImplementedError("Please implement this yourself.")

    @staticmethod
    def readStore(config):
        raise NotImplementedError("Please implement this yourself.")

class KeyTuple:
    def __init__(self, keyId, key, cert):
        self.keyId = keyId
        self.key = key
        self.cert = cert

class KeyStore(KeyStoreI):
    def __init__(self):
        self.keydict = dict()

    def getKey(self, keyId):
        if keyId not in self.keydict:
            return None
        return self.keydict[keyId].key

    def putKey(self, keyId, key, cert):
        self.keydict[keyId] = KeyTuple(keyId, key, cert)

    def putPEMCert(self, pemCert):
        cert = utils.loadCert(pemCert)
        pubKey = cert.public_key()
        serial = "%d" % cert.serial

        self.keydict[serial] = KeyTuple(serial, pubKey, cert)

    def putPEMKey(self, keyId, pemKey):
        pubKey = utils.loadPubKey(pemKey)

        self.keydict[keyId] = KeyTuple(keyId, pubKey, None)

    def writeStore(self, config):
        # TODO
        raise NotImplementedError("Please implement this yourself.")

    @staticmethod
    def readStore(config):
        # TODO
        raise NotImplementedError("Please implement this yourself.")
