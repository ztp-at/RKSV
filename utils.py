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
This module contains several utility functions regarding certificate and
key handling, as well has hashing, encoding and downloading receipts.
"""
from __future__ import unicode_literals
from builtins import int
from builtins import range

import gettext
_ = gettext.translation('rktool', './lang', fallback=True).gettext

import base64
import codecs
import datetime
import io
import json
import requests
import re
import uuid

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, Encoding, PublicFormat
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID

from six import string_types

def loadKeyFromJson(json):
    """
    Loads an AES-256 key from a cryptographic material container JSON.
    :param json: The JSON data.
    :return: The key as a byte list.
    """
    return base64.b64decode(json['base64AESKey'].encode('utf-8'))

def sha256(data):
    """
    Hashes the given data using SHA256.
    :param data: The data to be hashed as a byte list.
    :return: The hashed data as a byte list.
    """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()

def aes256ctr(iv, key, data):
    """
    Encrypts the given data using AES-256 in CTR mode with the given IV and key.
    Can also be used for decryption due to how the CTR mode works.
    :param iv: The IV as a byte list.
    :param key: The key as a byte list.
    :param data: The data to be encrypted as a byte list.
    :return: The encrypted data as a byte list.
    """
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend = default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def loadCert(pem):
    """
    Creates a cryptography certificate object from the given PEM certificate.
    :param pem: A certificate as a PEM string.
    :return: A cryptography certificate object.
    """
    return x509.load_pem_x509_certificate(pem.encode("utf-8"), default_backend())

def loadPubKey(pem):
    """
    Creates a cryptography public key object from the given PEM public key.
    :param pem: A public key as a PEM string.
    :return: A cryptography public key object.
    """
    return load_pem_public_key(pem.encode("utf-8"), default_backend())

def loadPrivKey(pem):
    """
    Creates a cryptography private key object from the given PEM private key.
    :param pem: A private key as a PEM string.
    :return: A cryptography private key object.
    """
    return load_pem_private_key(pem.encode("utf-8"), None, default_backend())

def exportCertToPEM(cert):
    """
    Converts a cryptography certificate object to a one-line PEM string without
    header and footer (i.e. the \"-----...\" lines).
    :param cert: The certificate object.
    :return: A string containing the PEM certificate.
    """
    pem = cert.public_bytes(Encoding.PEM).decode("utf-8").splitlines()[1:-1]
    return ''.join(pem)

def exportKeyToPEM(key):
    """
    Converts a cryptography public key object to a one-line PEM string without
    header and footer (i.e. the \"-----...\" lines).
    :param key: The public key object.
    :return: A string containing the PEM public key.
    """
    pem = key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8").splitlines()[1:-1]
    return ''.join(pem)

def addPEMCertHeaders(cert):
    """
    Adds a certificate header and footer to a PEM certificate string.
    :param cert: The PEM certificate string.
    :return: The PEM certificate string with header and footer.
    """
    return '-----BEGIN CERTIFICATE-----\n' + '\n'.join(
            [cert[i:i+64] for i in range(0, len(cert), 64)]
            ) + '\n-----END CERTIFICATE-----'

def addPEMPubKeyHeaders(pubKey):
    """
    Adds a public key header and footer to a PEM public key string.
    :param pubKey: The PEM public key string.
    :return: The PEM public key string with header and footer.
    """
    return '-----BEGIN PUBLIC KEY-----\n' + '\n'.join(
            [pubKey[i:i+64] for i in range(0, len(pubKey), 64)]
            ) + '\n-----END PUBLIC KEY-----'

def verifyCert(cert, signCert):
    """
    Verifies that a certificate has been signed with another. Note that this
    function only verifies the cryptographic signature and is probably wrong and
    dangerous. Do not use it to verify certificates. This function only supports
    ECDSA and RSA+PKCS1 signatures, all other signature types will fail.
    :param cert: The certificate whose signature we want to verify as a
    cryptography certificate object.
    :param signCert: The certificate that was used to sign the first certificate
    as a cryptography certificate object.
    :return: True if the signature is a valid ECDSA signature, False otherwise.
    """
    # FIXME: This is very likely wrong and we should find a better way to verify certs.
    halg = cert.signature_hash_algorithm
    sig = cert.signature
    data = cert.tbs_certificate_bytes

    pubKey = signCert.public_key()
    alg = None
    # We only support ECDSA and RSA+PKCS1
    if isinstance(pubKey, ec.EllipticCurvePublicKey):
        alg = ec.ECDSA(halg)
        ver = pubKey.verifier(sig, alg)
    elif isinstance(pubKey, rsa.RSAPublicKey):
        pad = padding.PKCS1v15()
        ver = pubKey.verifier(sig, pad, halg)
    else:
        return False

    ver.update(data)

    try:
        ver.verify()
        return True
    except InvalidSignature as e:
        return False

def certFingerprint(cert):
    """
    Gets a certificates SHA256 fingerprint.
    :param cert: The certificate as a cryptography certificate object.
    :return: The fingerprint as a string.
    """
    fp = cert.fingerprint(hashes.SHA256())
    if isinstance(fp, string_types):
        # Python 2
        return ':'.join('{:02x}'.format(ord(b)) for b in fp)
    else:
        # Python 3
        return ':'.join('{:02x}'.format(b) for b in fp)

def restoreb64padding(data):
    """
    Restores the padding to a base64 string without padding.
    :param data: The base64 encoded string without padding.
    :return: The base64 encoded string with padding.
    """
    needed = 4 - len(data) % 4
    if needed < 4:
        data += '=' * needed
    return data


urlsafe_b64Regex = re.compile(r'^[a-zA-Z0-9_-]*={0,3}$')
def urlsafe_b64decode(data):
    if not urlsafe_b64Regex.match(data.decode('utf-8')):
        raise TypeError
    return base64.urlsafe_b64decode(data)

b64Regex = re.compile(r'^[a-zA-Z0-9/+]*={0,3}$')
def b64decode(data):
    if not b64Regex.match(data.decode('utf-8')):
        raise TypeError
    return base64.b64decode(data)

b32Regex = re.compile(r'^[A-Z2-7/+]*={0,7}$')
def b32decode(data):
    if not b32Regex.match(data.decode('utf-8')):
        raise TypeError
    return base64.b32decode(data)

def getBasicCodeFromURL(url):
    """
    Downloads the basic code representation of a receipt from
    the given URL.
    :param url: The URL as a string.
    :return: The basic code representation as a string.
    """
    r = requests.get(url)
    r.raise_for_status()
    return r.json()['code']

urlHashRegex = re.compile(
        r'(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{11}(?![A-Za-z0-9_-])')
def getURLHashFromURL(url):
    """
    Extracts the URL hash from the given URL. If an anchor part is given,
    it is used as the hash.
    :param url: The URL to search for the hash.
    :return: The hash as a base64 URL encoded string without padding or
    None if the hash could not be found.
    """
    urlParts = url.split('#')
    if len(urlParts) >= 2:
        return urlParts[1]

    matches = urlHashRegex.findall(urlParts[0])
    if len(matches) == 0:
        return None

    return matches[-1]

def makeES256Keypair():
    """
    Generates a new EC key pair usable for JWS ES256.
    :return: The private and public key as objects.
    """
    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub = priv.public_key()
    return priv, pub

def makeCertSerial():
    """
    Generates a random serial number that can be used for a certificate.
    :return: The serial as an int.
    """
    return int(uuid.uuid4())

def makeSignedCert(cpub, ccn, cvdays, cserial, spriv, scert=None):
    """
    Creates a certificate for a given public key and signs it with a given
    certificate and private key. It will reuse the subject of the signing
    certificate as the subject of the new certificate, only replacing the
    common name with the one given as parameter, if a signing certificate is
    specified, otherwise it will just use the given common name as subject
    and issuer.
    :param cpub: Public key for which to create a certificate.
    :param ccn: Common name for the new certificate.
    :param cvdays: Number of days the new certificate is valid.
    :param cserial: The serial number for the new certificate as an int.
    :param spriv: Private key for the signing certificate.
    :param scert: Certificate used to sign the new certificate, or None if
    no certificate is used.
    :return: The new certificate as an object.
    """
    if scert:
        sname = x509.Name(
            [ p for p in scert.subject if p.oid != NameOID.COMMON_NAME ]
            + [ x509.NameAttribute(NameOID.COMMON_NAME, ccn) ])
        iname = scert.subject
    else:
        sname = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ccn)])
        iname = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ccn)])

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(sname)
    builder = builder.issuer_name(iname)
    builder = builder.not_valid_before(datetime.datetime.today())
    builder = builder.not_valid_after(datetime.datetime.today() +
            datetime.timedelta(cvdays, 0, 0))
    builder = builder.serial_number(cserial)
    builder = builder.public_key(cpub)
    builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
    )
    return builder.sign(private_key=spriv, algorithm=hashes.SHA256(),
            backend=default_backend())

receiptFloatRegex = re.compile(r'^-?([1-9]\d+|\d)\,\d\d$')
def getReceiptFloat(fstr):
    if receiptFloatRegex.match(fstr) is None:
        return None

    try:
        return float(fstr.replace(',', '.'))
    except:
        return None

def skipBOM(fd):
    """
    Removes the BOM from UTF-8 files so that we can live in peace.
    :param fd: The file descriptor that may or may not have a BOM at the start.
    :return: The position after the BOM as reported by fd.tell().
    """
    try:
        pos = fd.tell()
    except IOError:
        return 0

    if isinstance(fd, io.TextIOBase):
        fst = fd.read(len(codecs.BOM_UTF8.decode('utf-8')))
        if fst.encode('utf-8') != codecs.BOM_UTF8:
            fd.seek(pos)
    else:
        fst = fd.read(len(codecs.BOM_UTF8))
        if fst != codecs.BOM_UTF8:
            fd.seek(pos)

    return fd.tell()

def readJsonStream(stream):
    """
    Read a JSON file that may or may not have a BOM.
    """
    skipBOM(stream)
    return json.load(stream)

def cert_getstate(self):
    return exportCertToPEM(self)

def cert_setstate(self, cert_str):
    new_cert = loadCert(addPEMCertHeaders(cert_str))
    self.__dict__.update(new_cert.__dict__)

def pubkey_getstate(self):
    return exportKeyToPEM(self)

def pubkey_setstate(self, pubkey_str):
    new_pubkey = loadPubKey(addPEMPubKeyHeaders(pubkey_str))
    self.__dict__.update(new_pubkey.__dict__)

def cert_class_override(cert_class):
    """
    Overrides some methods or whatever class is passed as parameter. This
    is intended to allow for pickling/unpickling of certificate objects.
    """
    try:
        if cert_class.__pickle_override__:
            return
    except AttributeError:
        pass

    cert_class.__pickle_override__ = True
    cert_class.__getstate__ = cert_getstate
    cert_class.__setstate__ = cert_setstate

def pubkey_class_override(pubkey_class):
    """
    Overrides some methods or whatever class is passed as parameter. This
    is intended to allow for pickling/unpickling of public key objects.
    """
    try:
        if pubkey_class.__pickle_override__:
            return
    except AttributeError:
        pass

    pubkey_class.__pickle_override__ = True
    pubkey_class.__getstate__ = pubkey_getstate
    pubkey_class.__setstate__ = pubkey_setstate

# We need to initialize the pickle overrides for multiprocessing to work.
def init_class_overrides():
    s, p = makeES256Keypair()
    init_cert = makeSignedCert(p, 'init cert', 365, makeCertSerial(), s)
    cert_class_override(init_cert.__class__)
    pubkey_class_override(init_cert.public_key().__class__)

init_class_overrides()
