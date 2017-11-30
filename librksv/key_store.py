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
This module contains classes for a key store where certificates or public keys
can be stored under an identifier. Keys (and certificates) can also be retrieved
or deleted from the key store.
"""
from builtins import int
from builtins import range

import gettext
_ = gettext.translation('rktool', './lang', fallback=True).gettext

from six import string_types

import copy

from . import utils

class KeyStoreException(utils.RKSVException):
    def __init__(self, message):
        super(KeyStoreException, self).__init__(message)
        self._initargs = (message,)

    def __reduce__(self):
        return (self.__class__, self._initargs)

class KeyStoreParseException(KeyStoreException):
    """
    Indicates that an error occurred while parsing the key store.
    """

    def __init__(self, msg):
        super(KeyStoreParseException, self).__init__(msg)
        self._initargs = (msg,)

class MalformedKeyStoreException(KeyStoreParseException):
    """
    Indicates that the key store is not properly formed.
    """

    def __init__(self, msg=None, kid=None):
        if msg is None:
            super(MalformedKeyStoreException, self).__init__(_("Malformed key store"))
        else:
            if kid is None:
                super(MalformedKeyStoreException, self).__init__(
                        _('{}.').format(msg))
            else:
                super(MalformedKeyStoreException, self).__init__(
                        _("In certificate/public key \"{}\": {}.").format(kid, msg))
        self._initargs = (msg, kid)

class MissingKeyStoreElementException(MalformedKeyStoreException):
    """
    Indicates that an element in the key store is missing.
    """

    def __init__(self, elem, kid=None):
        super(MissingKeyStoreElementException, self).__init__(
                _("Element \"{}\" missing").format(elem),
                kid)
        self._initargs = (elem, kid)

class MalformedKeyStoreElementException(MalformedKeyStoreException):
    """
    Indicates that an element in the key store is malformed.
    """

    def __init__(self, elem, detail=None, kid=None):
        if detail is None:
            super(MalformedKeyStoreElementException, self).__init__(
                    _("Element \"{}\" malformed").format(elem),
                    kid)
        else:
            super(MalformedKeyStoreElementException, self).__init__(
                    _("Element \"{}\" malformed: {}").format(elem, detail),
                    kid)
        self._initargs = (elem, detail, kid)

class MalformedCertificateException(KeyStoreParseException):
    """
    Indicates that a certificate in the key store is not properly formed.
    """

    def __init__(self, kid):
        super(MalformedCertificateException, self).__init__(
                _("Certificate \"{}\" malformed.").format(kid))
        self._initargs = (kid,)

class MalformedPublicKeyException(KeyStoreParseException):
    """
    Indicates that a public key in the key store is not properly formed.
    """

    def __init__(self, kid):
        super(MalformedPublicKeyException, self).__init__(
                _("Public key \"{}\" malformed.").format(kid))
        self._initargs = (kid,)

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
        validKeyIds.append('%x' % int(serial, 16))
    except ValueError as e:
        pass

    try:
        validKeyIds.append('%x' % int(serial, 10))
    except ValueError as e:
        pass

    return validKeyIds

def parseKeyStoreCert(cert_str, kid):
    """
    Turns a certificate string as used in a key store into a certificate object.
    :param cert_str: A certificate in PEM format without header and footer
    and on a single line.
    :param kid: The key ID under which the cert is stored.
    :return: A cryptography certificate object.
    :throws: MalformedCertificateException
    """
    if not isinstance(cert_str, string_types):
        raise MalformedCertificateException(kid)

    try:
        return utils.loadCert(utils.addPEMCertHeaders(cert_str))
    except ValueError:
        raise MalformedCertificateException(kid)

def parseKeyStorePubkey(pubkey_str, kid):
    """
    Turns a public key string as used in a key store into a public key object.
    :param pubkey_str: A public key in PEM format without header and footer
    and on a single line.
    :param kid: The key ID under which the public key is stored.
    :return: A cryptography public key object.
    :throws: MalformedPublicKeyException
    """
    if not isinstance(pubkey_str, string_types):
        raise MalformedPublicKeyException(kid)

    try:
        return utils.loadPubKey(utils.addPEMPubKeyHeaders(pubkey_str))
    except ValueError:
        raise MalformedPublicKeyException(kid)

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
        :throws KeyStoreParseException
        """

        keyStore = KeyStore()

        if config.has_section('certificates'):
            for keyId, certStr in config.items('certificates'):
                keyId = keyId.replace('s;', 'S:')
                keyId = keyId.replace('u;', 'U:')
                keyId = keyId.replace('g;', 'G:')
                cert = parseKeyStoreCert(certStr, keyId)
                key = cert.public_key()
                keyStore.putKey(keyId, key, cert)
        if config.has_section('public_keys'):
            for keyId, keyStr in config.items('public_keys'):
                keyId = keyId.replace('s;', 'S:')
                keyId = keyId.replace('u;', 'U:')
                keyId = keyId.replace('g;', 'G:')
                key = parseKeyStorePubkey(keyStr, keyId)
                keyStore.putKey(keyId, key, None)

        return keyStore

    def writeStoreToJson(self, b64Key):
        """
        Writes the store to a JSON structure that is compatible with the JSON
        crypto container format and can be used with json.dumps().
        :param b64Key: The AES256 key to attach to the container as a base64
        encoded string or None if the key is not known.
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

        ret = { 'certificateOrPublicKeyMap': kDict }
        if b64Key is not None:
            ret['base64AESKey'] = b64Key

        return ret

    @staticmethod
    def readStoreFromJson(json):
        """
        Reads a key store from the given JSON crypto container object.
        :param json: The JSON container.
        :return: A KeyStore object.
        :throws KeyStoreParseException
        """

        if not isinstance(json, dict):
            raise MalformedKeyStoreException(_('Malformed key store root'))

        if 'certificateOrPublicKeyMap' not in json:
            raise MissingKeyStoreElementException('certificateOrPublicKeyMap')

        cpmap = json['certificateOrPublicKeyMap']
        if not isinstance(cpmap, dict):
            raise MalformedKeyStoreElementException('certificateOrPublicKeyMap',
                    _('not a dictionary'))

        keyStore = KeyStore()

        for rawId, value in cpmap.items():
            if not isinstance(value, dict):
                raise MalformedKeyStoreElementException('certificateOrPublicKeyMap',
                    _('not a dictionary'), rawId)

            if 'id' not in value:
                raise MissingKeyStoreElementException('id', rawId)
            if 'signatureDeviceType' not in value:
                raise MissingKeyStoreElementException('signatureDeviceType', rawId)
            if 'signatureCertificateOrPublicKey' not in value:
                raise MissingKeyStoreElementException(
                        'signatureCertificateOrPublicKey', rawId)

            innerId = value['id']
            if not isinstance(innerId, string_types):
                raise MalformedKeyStoreElementException('id', _('not a string'),
                        rawId)
            if rawId != innerId:
                raise MalformedKeyStoreElementException('id',
                        _('inner ID \"{}\" does not match outer ID \"{}\"').format(
                            innerId, rawId), rawId)

            devType = value['signatureDeviceType']
            if not isinstance(devType, string_types):
                raise MalformedKeyStoreElementException('signatureDeviceType',
                        _('not a string'), rawId)

            cpStr = value['signatureCertificateOrPublicKey']

            keyId = None
            key = None
            cert = None

            if devType == 'CERTIFICATE':
                certIds = strSerialToKeyIds(rawId)
                if len(certIds) < 1:
                    raise MalformedKeyStoreElementException('id',
                            _('invalid certificate ID \"{}\"').format(rawId), rawId)
                keyId = certIds[0]
                cert = parseKeyStoreCert(cpStr, keyId)
                key = cert.public_key()
            elif devType == 'PUBLIC_KEY':
                keyId = value['id']
                key = parseKeyStorePubkey(cpStr, keyId)
            else:
                raise MalformedKeyStoreElementException('signatureDeviceType',
                        _('not one of \"CERTIFICATE\" or \"PUBLIC_KEY\"'), rawId)

            keyStore.putKey(keyId, key, cert)

        return keyStore
