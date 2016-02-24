import algorithms
import rechnung
import utils

class UnknownAlgorithmException(rechnung.ReceiptException):
    def __init__(self, receipt):
        super(UnknownAlgorithmException, self).__init__(receipt, "Unknown algorithm.")

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

    def verify(self, receipt, algorithmPrefix):
        jwsString = receipt.toJWSString(algorithmPrefix)

        if algorithmPrefix not in algorithms.ALGORITHMS:
            raise UnknownAlgorithmException(jwsString)
        algorithm = algorithms.ALGORITHMS[algorithmPrefix]

        validationSuccessful = algorithm.verify(jwsString, depCert2PEM(self.cert))

        serial = utils.loadCert(depCert2PEM(self.cert)).serial
        # for some reason the ref impl has a negative serial on some certs
        if serial != receipt.certSerial and -serial != receipt.certSerial:
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
