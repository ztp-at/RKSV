#!/usr/bin/python3

"""
This module contains classes to verify receipts.
"""
import enum

import algorithms
import key_store
import rechnung
import utils

class CertSerialMismatchException(rechnung.ReceiptException):
    """
    Indicates that the certificate serial in the receipt and the certificate in
    the DEP group to not match.
    """
    def __init__(self, receipt):
        super(CertSerialMismatchException, self).__init__(receipt, "Certificate serial mismatch.")

class CertSerialInvalidException(rechnung.ReceiptException):
    """
    Indicates that the certificate serial in the receipt is malformed.
    """
    def __init__(self, receipt):
        super(CertSerialInvalidException, self).__init__(receipt, "Certificate serial invalid.")

class NoPublicKeyException(rechnung.ReceiptException):
    """
    Indicates that no public key to verify the signature of the receipt could be
    found.
    """
    def __init__(self, receipt):
        super(NoPublicKeyException, self).__init__(receipt, "No public key found.")

class InvalidSignatureException(rechnung.ReceiptException):
    """
    Indicates that the signature of the receipt is invalid.
    """
    def __init__(self, receipt):
        super(InvalidSignatureException, self).__init__(receipt, "Invalid Signature.")

class SignatureSystemFailedException(rechnung.ReceiptException):
    """
    Indicates that the signature system failed and that the receipt was not
    signed.
    """
    def __init__(self, receipt):
        super(SignatureSystemFailedException, self).__init__(receipt, "Signature System failed.")

class ReceiptVerifierI:
    """
    The base class for receipt verifiers. It contains functions that every
    receipt verifier must implement. Do not use this directly.
    """

    def verify(self, receipt, algorithmPrefix):
        """
        Verifies the given receipt using the algorithm specified.
        :param receipt: The signed receipt object to verify.
        :param algorithmPrefix: The ID of the algorithm class used as a string.
        This should match the algorithm used to sign the receipt.
        :returns: The receipt object and the used algorithm class object.
        :throws: CertSerialInvalidException
        :throws: CertSerialMismatchException
        :throws: NoPublicKeyException
        :throws: InvalidSignatureException
        :throws: UnknownAlgorithmException
        :throws: InvalidSignatureException
        :throws: SignatureSystemFailedException
        """
        raise NotImplementedError("Please implement this yourself.")

    def verifyJWS(self, jwsString):
        """
        Verifies the given receipt.
        :param jwsString: The receipt as jwsString.
        :returns: The receipt object and the used algorithm class object.
        :throws: CertSerialInvalidException
        :throws: CertSerialMismatchException
        :throws: NoPublicKeyException
        :throws: InvalidSignatureException
        :throws: UnknownAlgorithmException
        :throws: InvalidSignatureException
        :throws: SignatureSystemFailedException
        :throws: MalformedReceiptException
        :throws: AlgorithmMismatchException
        """
        raise NotImplementedError("Please implement this yourself.")

    def verifyBasicCode(self, basicCode):
        """
        Verifies the given receipt.
        :param basicCode: The receipt as QR code string.
        :returns: The receipt object and the used algorithm class object.
        :throws: CertSerialInvalidException
        :throws: CertSerialMismatchException
        :throws: NoPublicKeyException
        :throws: InvalidSignatureException
        :throws: UnknownAlgorithmException
        :throws: InvalidSignatureException
        :throws: SignatureSystemFailedException
        :throws: MalformedReceiptException
        """
        raise NotImplementedError("Please implement this yourself.")

class CertSerialType(enum.Enum):
    """
    An enum for all the different types of certificate serials
    """
    SERIAL = 0
    TAX = 1
    UID = 2
    GLN = 3
    INVALID = 4

    @staticmethod
    def getCertSerialType(certSerial):
        """
        Parses the given serial to determine its type.
        :param certSerial: The serial from a receipt as string.
        :return: The type of the serial or INVALID if the serial is malformed.
        """
        parts = certSerial.split('-')
        certSerial = parts[0]
        if len(parts) > 2:
            return CertSerialType.INVALID
        elif len(parts) == 2:
            if not parts[1].isalnum():
                return CertSerialType.INVALID

        if len(certSerial) == 11 and certSerial[0:2] == 'S:' and certSerial[2:].isdigit():
            return CertSerialType.TAX
        elif len(certSerial) >= 3 and len(certSerial) <= 16 and certSerial[0:2] == 'U:'  and certSerial[2:].isalnum():
            return CertSerialType.UID
        elif len(certSerial) == 15 and certSerial[0:2] == 'G:' and certSerial[2:].isdigit():
            return CertSerialType.GLN
        else:
            try:
                # TODO: update this for HEX
                int(certSerial, 10)
                return CertSerialType.SERIAL
            except ValueError as e:
                return CertSerialType.INVALID

class ReceiptVerifier(ReceiptVerifierI):
    """
    A simple implementation of a receipt verifier.
    """

    def __init__(self, keyStore, cert):
        """
        Creates a new receipt verifier. At least one of the two parameters has
        to be set.
        :param keyStore: The key store object to use to obtain public keys or
        None.
        :param cert: The certificate to verify the receipts with as a
        cryptography certificate object.
        """
        self.keyStore = keyStore
        self.cert = cert

    @staticmethod
    def fromDEPCert(depCert):
        """
        Creates a new receipt verifier from a certificate as it is stored in a
        DEP.
        :param depCert: The certificate as a PEM formatted string without header
        and footer.
        :return: The new receipt verifier.
        """
        cert = utils.loadCert(utils.addPEMCertHeaders(depCert))

        return ReceiptVerifier(None, cert)

    @staticmethod
    def fromKeyStore(keyStore):
        """
        Creates a new receipt verifier from a key store object.
        :param keyStore: The key store object.
        :return: The new receipt verifier.
        """
        return ReceiptVerifier(keyStore, None)

    def verify(self, receipt, algorithmPrefix):
        jwsString = receipt.toJWSString(algorithmPrefix)

        if algorithmPrefix not in algorithms.ALGORITHMS:
            raise rechnung.UnknownAlgorithmException(jwsString)
        algorithm = algorithms.ALGORITHMS[algorithmPrefix]

        certSerial = key_store.preprocCertSerial(receipt.certSerial)
        certSerialType = CertSerialType.getCertSerialType(certSerial)
        if certSerialType == CertSerialType.INVALID:
            raise CertSerialInvalidException(jwsString)

        pubKey = None
        if self.cert:
            if certSerialType == CertSerialType.SERIAL:
                if key_store.preprocCertSerial("%d" % self.cert.serial) != certSerial:
                    raise CertSerialMismatchException(jwsString)
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
    config.optionxform = str
    config.read(sys.argv[2])
    keyStore = key_store.KeyStore.readStore(config)
    rv = ReceiptVerifier.fromKeyStore(keyStore)

    if len(sys.argv) == 4:
        INPUT_FORMATS[sys.argv[1]](rv, sys.argv[3])
    else:
        for l in sys.stdin:
            INPUT_FORMATS[sys.argv[1]](rv, l.strip())
