#!/usr/bin/python3

import algorithms
import rechnung
import utils

class CertSerialMismatchException(rechnung.ReceiptException):
    def __init__(self, receipt):
        super(CertSerialMismatchException, self).__init__(receipt, "Certificate serial mismatch.")

class InvalidSignatureException(rechnung.ReceiptException):
    def __init__(self, receipt):
        super(InvalidSignatureException, self).__init__(receipt, "Invalid Signature.")

class SignatureSystemFailedException(rechnung.ReceiptException):
    def __init__(self, receipt):
        super(SignatureSystemFailedException, self).__init__(receipt, "Signature System failed.")

def depCert2PEM(depCert):
    return '-----BEGIN CERTIFICATE-----\n' + depCert +  '\n-----END CERTIFICATE-----'

class ReceiptVerifierI:
    def verify(self, receipt, algorithmPrefix):
        raise NotImplementedError("Please implement this yourself.")

    def verifyJWS(self, jwsString):
        raise NotImplementedError("Please implement this yourself.")

class ReceiptVerifier(ReceiptVerifierI):
    def __init__(self, cert):
        self.cert = cert

    @staticmethod
    def fromDEPCert(depCert):
        return ReceiptVerifier(depCert2PEM(depCert))

    def verify(self, receipt, algorithmPrefix):
        jwsString = receipt.toJWSString(algorithmPrefix)

        if algorithmPrefix not in algorithms.ALGORITHMS:
            raise rechnung.UnknownAlgorithmException(jwsString)
        algorithm = algorithms.ALGORITHMS[algorithmPrefix]

        validationSuccessful = algorithm.verify(jwsString, self.cert)

        serial = "%d" % utils.loadCert(self.cert).serial
        # for some reason the ref impl has a negative serial on some certs
        if serial != receipt.certSerial and '-' + serial != receipt.certSerial:
            raise CertSerialMismatchException(jwsString)

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

import sys

INPUT_FORMATS = {
        'jws': lambda rv, s: rv.verifyJWS(s),
        'qr': lambda rv, s: rv.verifyBasicCode(s)
        }

if __name__ == "__main__":
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Usage: ./verify_receipt.py <format> <cert file> [<receipt string>]")
        sys.exit(0)

    if sys.argv[1] not in INPUT_FORMATS:
        print("Input format must be one of %s." % INPUT_FORMATS.keys())
        sys.exit(0)

    rv = None
    with open(sys.argv[2]) as f:
        rv = ReceiptVerifier(f.read())

    if len(sys.argv) == 4:
        INPUT_FORMATS[sys.argv[1]](rv, sys.argv[3])
    else:
        for l in sys.stdin:
            INPUT_FORMATS[sys.argv[1]](rv, l.strip())
