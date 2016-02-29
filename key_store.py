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

    def getKeyIds(self):
        return self.keydict.keys()

    def getKey(self, keyId):
        if keyId not in self.keydict:
            return None
        return self.keydict[keyId].key

    def getCert(self, keyId):
        if keyId not in self.keydict:
            return None
        return self.keydict[keyId].cert

    def putKey(self, keyId, key, cert):
        self.keydict[keyId] = KeyTuple(keyId, key, cert)

    def delKey(self, keyId):
        if keyId not in self.keydict:
            return
        del self.keydict[keyId]

    def putPEMCert(self, pemCert):
        cert = utils.loadCert(pemCert)
        pubKey = cert.public_key()
        serial = "%d" % cert.serial

        self.keydict[serial] = KeyTuple(serial, pubKey, cert)

    def putPEMKey(self, keyId, pemKey):
        pubKey = utils.loadPubKey(pemKey)

        self.keydict[keyId] = KeyTuple(keyId, pubKey, None)

    def writeStore(self, config):
        if not config.has_section('certificates'):
            config.add_section('certificates')
        if not config.has_section('public_keys'):
            config.add_section('public_keys')

        for keyId, kt in self.keydict.items():
            if kt.cert:
                config.set('certificates', keyId,
                        utils.exportCertToPEM(kt.cert))
            else:
                config.set('public_keys', keyId,
                        utils.exportKeyToPEM(kt.key))

    @staticmethod
    def readStore(config):
        keyStore = KeyStore()

        if config.has_section('certificates'):
            for keyId, certStr in config.items('certificates'):
                cert = utils.loadCert(utils.addPEMCertHeaders(certStr))
                key = cert.public_key()
                keyStore.putKey(keyId, key, cert)
        if config.has_section('public_keys'):
            for keyId, keyStr in config.items('public_keys'):
                key = utils.loadPubKey(utils.addPEMPubKeyHeaders(keyStr))
                keyStore.putKey(keyId, key, None)

        return keyStore

import configparser
import sys

def usage():
    print("Usage: ./key_store.py <key store> create")
    print("       ./key_store.py <key store> list")
    print("       ./key_store.py <key store> add <pem cert file>")
    print("       ./key_store.py <key store> add <pem pubkey file> <pubkey id>")
    print("       ./key_store.py <key store> del <pubkey id|cert serial>")
    sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()

    filename = sys.argv[1]
    keyStore = None

    if sys.argv[2] == 'create':
        if len(sys.argv) != 3:
            usage()

        keyStore = KeyStore()

    elif sys.argv[2] == 'list':
        if len(sys.argv) != 3:
            usage()

        config = configparser.RawConfigParser()
        config.read(filename)
        keyStore = KeyStore.readStore(config)

        for keyId in keyStore.getKeyIds():
            print(keyId)

    elif sys.argv[2] == 'add':
        if len(sys.argv) < 4:
            usage()

        config = configparser.RawConfigParser()
        config.read(filename)
        keyStore = KeyStore.readStore(config)

        newKey = None
        with open(sys.argv[3]) as f:
            newKey = f.read()

        if len(sys.argv) == 4:
            keyStore.putPEMCert(newKey)
        elif len(sys.argv) == 5:
            keyStore.putPEMKey(sys.argv[4], newKey)
        else:
            usage()

    elif sys.argv[2] == 'del':
        if len(sys.argv) != 4:
            usage()

        config = configparser.RawConfigParser()
        config.read(filename)
        keyStore = KeyStore.readStore(config)

        keyStore.delKey(sys.argv[3])

    else:
        usage()

    config = configparser.RawConfigParser()
    keyStore.writeStore(config)
    with open(filename, 'w') as f:
        config.write(f)
