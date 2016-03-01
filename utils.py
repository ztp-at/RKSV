from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, PublicFormat
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def sha256(data):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()

def aes256ctr(iv, key, data):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend = default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def loadCert(pem):
    return x509.load_pem_x509_certificate(pem.encode("utf-8"), default_backend())

def loadPubKey(pem):
    return load_pem_public_key(pem.encode("utf-8"), default_backend())

def exportCertToPEM(key):
    pem = key.public_bytes(Encoding.PEM).decode("utf-8").splitlines()[1:-1]
    return ''.join(pem)

def exportKeyToPEM(key):
    pem = key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8").splitlines()[1:-1]
    return ''.join(pem)

def addPEMCertHeaders(cert):
    return '-----BEGIN CERTIFICATE-----\n' + cert + '\n-----END CERTIFICATE-----'

def addPEMPubKeyHeaders(pubKey):
    return '-----BEGIN PUBLIC KEY-----\n' + pubKey + '\n-----END PUBLIC KEY-----'

def verifyCert(cert, signCert):
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
