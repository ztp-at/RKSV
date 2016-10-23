#!/bin/env python2.7

"""
This module contains classes for a key store where certificates or public keys
can be stored under an identifier. Keys (and certificates) can also be retrieved
or deleted from the key store.
"""
from builtins import int

import copy
import numbers

import utils

class KeyStoreI(object):
    """
    The base class for a key store. It contains functions every key store must
    implement. Do not use this directly.
    """

    def getKeyIds(self):
        """
        Gets the IDs of all keys stored in the key store.
        :return A list of the key IDs as strings.
        """
        raise NotImplementedError("Please implement this yourself.")

    def getKey(self, keyId):
        """
        Gets the key stored under the given ID.
        :param keyId: The ID of the key to get as a string.
        :return: The public key as a cryptography key object or None if no key
        is stored under the given ID.
        """
        raise NotImplementedError("Please implement this yourself.")

    def getCert(self, keyId):
        """
        Gets the certificate stored under the given ID.
        :param keyId: The ID of the certificate to get as a string.
        :return: The certificate as a cryptography certificate object or None if
        no certificate is stored under the given ID.
        """
        raise NotImplementedError("Please implement this yourself.")

    def putKey(self, keyId, key, cert):
        """
        Stores the given key under the given ID in the key store.
        :param keyId: The ID as a string.
        :param key: The public key as a cryptography key object.
        :param cert: The certificate as a cryptography certificate object or
        None if no certificate for the public key is known.
        """
        raise NotImplementedError("Please implement this yourself.")

    def delKey(self, keyId):
        """
        Deletes the key stored under the given ID from the key store.
        :param keyId: The ID as a string.
        """
        raise NotImplementedError("Please implement this yourself.")

    def putPEMCert(self, pemCert):
        """
        Stores a PEM certificate in the key store using the certificate's serial
        as an ID.
        :param pemCert: The certificate as a PEM formatted string.
        """
        raise NotImplementedError("Please implement this yourself.")

    def putPEMKey(self, keyId, pemKey):
        """
        Stores a PEM public key in the key store using the given ID.
        :param keyId: The ID as a string.
        :param pemKey: The public key as a PEM formatted string.
        """
        raise NotImplementedError("Please implement this yourself.")

def numSerialToKeyId(serial):
    """
    Converts a certificate serial to a hexadecimal key ID.
    :param serial: The serial as a number.
    :return: The key ID as a string.
    """
    return ('%x' % abs(serial))

def strSerialToKeyIds(serial):
    """
    Generates all possible key IDs as which a certificate serial could be
    interpreted. As serials may be represented as either decimal or hexadecimal
    strings there may be multiple valid conversions to key IDs.
    :param serial: The serial as a decimal or hexadecimal string.
    :return: A list of possible key IDs, where each entry is a string. May be
    empty if the serial is invalid.
    """
    # for some reason the ref impl has a negative serial on some certs
    if serial[0] == '-':
        serial = serial[1:]

    validKeyIds = list()

    try:
        int(serial, 16)
        validKeyIds.append(serial.lower())
    except ValueError as e:
        pass

    try:
        validKeyIds.append('%x' % int(serial, 10))
    except ValueError as e:
        pass

    return validKeyIds

class KeyTuple(object):
    """
    The data structure used internally by KeyStore. For internal use only.
    """

    def __init__(self, keyId, key, cert):
        self.keyId = keyId
        self.key = key
        self.cert = cert

class KeyStore(KeyStoreI):
    """
    A basic implementation of a key store. It allows writing the store to and
    reading it from an .ini file using a config parser.

    Note that key IDs starting with \"S:\", \"U:\" or \"G:\" are stored as
    \"s;...\", \"u;...\" and \"g;...\" respectively because the default config parser
    does not support a colon in the key ID.
    """

    def __deepcopy__(self, memo):
        cp = KeyStore()
        cp.keydict = copy.copy(self.keydict)
        return cp

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
        serial = numSerialToKeyId(cert.serial)

        self.keydict[serial] = KeyTuple(serial, pubKey, cert)

    def putPEMKey(self, keyId, pemKey):
        pubKey = utils.loadPubKey(pemKey)

        self.keydict[keyId] = KeyTuple(keyId, pubKey, None)

    def writeStore(self, config):
        """
        Writes the store to the given config parser. The used parser must not
        modify the case of the keys.
        :param config: The config parser.
        """

        if not config.has_section('certificates'):
            config.add_section('certificates')
        if not config.has_section('public_keys'):
            config.add_section('public_keys')

        for keyId, kt in self.keydict.items():
            keyId = keyId.replace('S:', 's;')
            keyId = keyId.replace('U:', 'u;')
            keyId = keyId.replace('G:', 'g;')
            if kt.cert:
                config.set('certificates', keyId,
                        utils.exportCertToPEM(kt.cert))
            else:
                config.set('public_keys', keyId,
                        utils.exportKeyToPEM(kt.key))

    @staticmethod
    def readStore(config):
        """
        Reads a key store from the given config parser and returns it as an
        object. The used parser must not modify the case of the keys.
        :param config: The config parser.
        :return: A KeyStore object.
        """

        keyStore = KeyStore()

        if config.has_section('certificates'):
            for keyId, certStr in config.items('certificates'):
                keyId = keyId.replace('s;', 'S:')
                keyId = keyId.replace('u;', 'U:')
                keyId = keyId.replace('g;', 'G:')
                cert = utils.loadCert(utils.addPEMCertHeaders(certStr))
                key = cert.public_key()
                keyStore.putKey(keyId, key, cert)
        if config.has_section('public_keys'):
            for keyId, keyStr in config.items('public_keys'):
                keyId = keyId.replace('s;', 'S:')
                keyId = keyId.replace('u;', 'U:')
                keyId = keyId.replace('g;', 'G:')
                key = utils.loadPubKey(utils.addPEMPubKeyHeaders(keyStr))
                keyStore.putKey(keyId, key, None)

        return keyStore

    def writeStoreToJson(self):
        """
        Writes the store to a JSON structure that is compatible with the JSON
        crypto container format and can be used with json.dumps().
        :return: The JSON container.
        """

        kDict = dict()
        for keyId, kt in self.keydict.items():
            cont = dict()

            cont['id'] = keyId
            if kt.cert:
                cont['signatureDeviceType'] = 'CERTIFICATE'
                cont['signatureCertificateOrPublicKey'] = utils.exportCertToPEM(kt.cert)
            else:
                cont['signatureDeviceType'] = 'PUBLIC_KEY'
                cont['signatureCertificateOrPublicKey'] = utils.exportKeyToPEM(kt.key)

            kDict[keyId] = cont

        return {'certificateOrPublicKeyMap': kDict}

    @staticmethod
    def readStoreFromJson(json):
        """
        Reads a key store from the given JSON crypto container object.
        :param json: The JSON container.
        :return: A KeyStore object.
        """

        keyStore = KeyStore()

        for value in json['certificateOrPublicKeyMap'].values():
            keyStr = value['signatureCertificateOrPublicKey']

            keyId = None
            key = None
            cert = None
            if value['signatureDeviceType'] == 'CERTIFICATE':
                keyId = strSerialToKeyIds(value['id'])[0]
                cert = utils.loadCert(utils.addPEMCertHeaders(keyStr))
                key = cert.public_key()
            else:
                keyId = value['id']
                key = utils.loadPubKey(utils.addPEMPubKeyHeaders(keyStr))

            keyStore.putKey(keyId, key, cert)

        return keyStore

def usage():
    print("Usage: ./key_store.py <key store> create")
    print("       ./key_store.py <key store> list")
    print("       ./key_store.py <key store> toJson")
    print("       ./key_store.py <key store> fromJson <json container file>")
    print("       ./key_store.py <key store> add <pem cert file>")
    print("       ./key_store.py <key store> add <pem pubkey file> <pubkey id>")
    print("       ./key_store.py <key store> del <pubkey id|cert serial>")
    sys.exit(0)

if __name__ == "__main__":
    import gettext
    gettext.install('rktool', './lang', True)

    import configparser
    import json
    import sys

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
        config.optionxform = str
        config.read(filename)
        keyStore = KeyStore.readStore(config)

        for keyId in keyStore.getKeyIds():
            print(keyId)

    elif sys.argv[2] == 'toJson':
        if len(sys.argv) != 3:
            usage()

        config = configparser.RawConfigParser()
        config.optionxform = str
        config.read(filename)
        keyStore = KeyStore.readStore(config)

        data = keyStore.writeStoreToJson()
        print(json.dumps(data, sort_keys=False, indent=2))

    elif sys.argv[2] == 'fromJson':
        if len(sys.argv) != 4:
            usage()

        keyStore = None
        with open(sys.argv[3]) as f:
            keyStore = KeyStore.readStoreFromJson(json.loads(f.read()))

    elif sys.argv[2] == 'add':
        if len(sys.argv) < 4:
            usage()

        config = configparser.RawConfigParser()
        config.optionxform = str
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
        config.optionxform = str
        config.read(filename)
        keyStore = KeyStore.readStore(config)

        keyStore.delKey(sys.argv[3])

    else:
        usage()

    config = configparser.RawConfigParser()
    config.optionxform = str
    keyStore.writeStore(config)
    with open(filename, 'w') as f:
        config.write(f)
