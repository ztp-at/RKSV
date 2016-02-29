#!/usr/bin/python3

import algorithms
import key_store
import rechnung
import utils

class CertSerialMismatchException(rechnung.ReceiptException):
    def __init__(self, receipt):
        super(CertSerialMismatchException, self).__init__(receipt, "Certificate serial mismatch.")

class NoPublicKeyException(rechnung.ReceiptException):
    def __init__(self, receipt):
        super(NoPublicKeyException, self).__init__(receipt, "No public key found.")

class InvalidSignatureException(rechnung.ReceiptException):
    def __init__(self, receipt):
        super(InvalidSignatureException, self).__init__(receipt, "Invalid Signature.")

class SignatureSystemFailedException(rechnung.ReceiptException):
    def __init__(self, receipt):
        super(SignatureSystemFailedException, self).__init__(receipt, "Signature System failed.")

class ReceiptVerifierI:
    def verify(self, receipt, algorithmPrefix):
        raise NotImplementedError("Please implement this yourself.")

    def verifyJWS(self, jwsString):
        raise NotImplementedError("Please implement this yourself.")

class ReceiptVerifier(ReceiptVerifierI):
    def __init__(self, keyStore, cert):
        self.keyStore = keyStore
        self.cert = cert

    @staticmethod
    def fromDEPCert(depCert):
        cert = utils.loadCert(utils.addPEMCertHeaders(depCert))

        return ReceiptVerifier(None, cert)

    @staticmethod
    def fromKeyStore(keyStore):
        return ReceiptVerifier(keyStore, None)

    def verify(self, receipt, algorithmPrefix):
        jwsString = receipt.toJWSString(algorithmPrefix)

        if algorithmPrefix not in algorithms.ALGORITHMS:
            raise rechnung.UnknownAlgorithmException(jwsString)
        algorithm = algorithms.ALGORITHMS[algorithmPrefix]

        certSerial = receipt.certSerial
        # for some reason the ref impl has a negative serial on some certs
        if certSerial[0] == '-':
            certSerial = certSerial[1:]

        # TODO: validate form of serial/keyId

        pubKey = None
        if self.cert:
            # TODO: if cert, validate that cert serials match
            pubKey = self.cert.public_key()
        else:
            pubKey = self.keyStore.getKey(certSerial)

        if not pubKey:
            raise NoPublicKeyException(jwsString)

        validationSuccessful = algorithm.verify(jwsString, pubKey)

        if not validationSuccessful:
            if receipt.isSignedBroken():
                raise SignatureSystemFailedException(jwsString)
            else:
                raise InvalidSignatureException(jwsString)

        return receipt, algorithm

    def verifyJWS(self, jwsString):
        receipt, algorithmPrefix = rechnung.Rechnung.fromJWSString(jwsString)

        return self.verify(receipt, algorithmPrefix)

    def verifyBasicCode(self, basicCode):
        receipt, algorithmPrefix = rechnung.Rechnung.fromBasicCode(basicCode)

        return self.verify(receipt, algorithmPrefix)

import configparser
import sys

INPUT_FORMATS = {
        'jws': lambda rv, s: rv.verifyJWS(s),
        'qr': lambda rv, s: rv.verifyBasicCode(s)
        }

if __name__ == "__main__":
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Usage: ./verify_receipt.py <format> <key store> [<receipt string>]")
        sys.exit(0)

    if sys.argv[1] not in INPUT_FORMATS:
        print("Input format must be one of %s." % INPUT_FORMATS.keys())
        sys.exit(0)

    rv = None
    config = configparser.RawConfigParser()
    config.read(sys.argv[2])
    keyStore = key_store.KeyStore.readStore(config)
    rv = ReceiptVerifier.fromKeyStore(keyStore)

    if len(sys.argv) == 4:
        INPUT_FORMATS[sys.argv[1]](rv, sys.argv[3])
    else:
        for l in sys.stdin:
            INPUT_FORMATS[sys.argv[1]](rv, l.strip())
