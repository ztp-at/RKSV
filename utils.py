"""
This module contains several utility functions regarding certificate and key
handling.
"""
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, PublicFormat
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

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
    return '-----BEGIN CERTIFICATE-----\n' + cert + '\n-----END CERTIFICATE-----'

def addPEMPubKeyHeaders(pubKey):
    """
    Adds a public key header and footer to a PEM public key string.
    :param pubKey: The PEM public key string.
    :return: The PEM public key string with header and footer.
    """
    return '-----BEGIN PUBLIC KEY-----\n' + pubKey + '\n-----END PUBLIC KEY-----'

def verifyCert(cert, signCert):
    """
    Verifies that a certificate has been signed with another. Note that this
    function only verifies the cryptographic signature and is probably wrong and
    dangerous. Do not use it to verify certificates. This function only supports
    ECDSA signatures, all other signature types will fail.
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
    # We only support ECDSA for now
    if isinstance(pubKey, ec.EllipticCurvePublicKey):
        alg = ec.ECDSA(halg)
    else:
        return False

    ver = pubKey.verifier(sig, alg)
    ver.update(data)

    try:
        ver.verify()
        return True
    except InvalidSignature as e:
        return False
