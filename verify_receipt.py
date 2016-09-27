#!/usr/bin/python3

"""
This module contains classes to verify receipts.
"""
from builtins import int

import base64
import enum

import algorithms
import key_store
import receipt
import utils

class CertSerialMismatchException(receipt.ReceiptException):
    """
    Indicates that the certificate serial in the receipt and the certificate in
    the DEP group to not match.
    """
    def __init__(self, rec):
        super(CertSerialMismatchException, self).__init__(rec, _("Certificate serial mismatch."))

class CertSerialInvalidException(receipt.ReceiptException):
    """
    Indicates that the certificate serial in the receipt is malformed.
    """
    def __init__(self, rec):
        super(CertSerialInvalidException, self).__init__(rec, _("Certificate serial invalid."))

class NoPublicKeyException(receipt.ReceiptException):
    """
    Indicates that no public key to verify the signature of the receipt could be
    found.
    """
    def __init__(self, rec):
        super(NoPublicKeyException, self).__init__(rec, _("No public key found."))

class InvalidSignatureException(receipt.ReceiptException):
    """
    Indicates that the signature of the receipt is invalid.
    """
    def __init__(self, rec):
        super(InvalidSignatureException, self).__init__(rec, _("Invalid Signature."))

class SignatureSystemFailedException(receipt.ReceiptException):
    """
    Indicates that the signature system failed and that the receipt was not
    signed.
    """
    def __init__(self, rec):
        super(SignatureSystemFailedException, self).__init__(rec, _("Signature System failed."))

class InvalidURLHashException(receipt.ReceiptException):
    """
    Indicates that the given URL hash does not match the URL hash computed
    from the receipt.
    """
    def __init__(self, rec):
        super(InvalidURLHashException, self).__init__(rec, _("Invalid URL hash."))

class InvalidCertificateProviderException(receipt.ReceiptException):
    """
    Indicates that the given certificate provider (ZDA) is invalid.
    This usually means that AT0 was used in an open system or not used
    in a closed system.
    """
    def __init__(self, rec):
        super(InvalidCertificateProviderException, self).__init__(rec, _("Invalid certificate provider."))

class UnsignedNullReceiptException(receipt.ReceiptException):
    """
    Indicates that a non-dummy and non-reversal null receipt has not been
    signed.
    """
    def __init__(self, rec):
        super(UnsignedNullReceiptException, self).__init__(rec, _("Null receipt not signed."))

class ReceiptVerifierI:
    """
    The base class for receipt verifiers. It contains functions that every
    receipt verifier must implement. Do not use this directly.
    """

    def verify(self, rec, algorithmPrefix):
        """
        Verifies the given receipt using the algorithm specified.
        :param rec: The signed receipt object to verify.
        :param algorithmPrefix: The ID of the algorithm class used as a string.
        This should match the algorithm used to sign the receipt.
        :returns: The receipt object and the used algorithm class object.
        :throws: CertSerialInvalidException
        :throws: CertSerialMismatchException
        :throws: NoPublicKeyException
        :throws: InvalidSignatureException
        :throws: UnknownAlgorithmException
        :throws: SignatureSystemFailedException
        :throws: UnsignedNullReceiptException
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
        :throws: SignatureSystemFailedException
        :throws: MalformedReceiptException
        :throws: AlgorithmMismatchException
        :throws: UnsignedNullReceiptException
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
        :throws: SignatureSystemFailedException
        :throws: MalformedReceiptException
        :throws: UnsignedNullReceiptException
        """
        raise NotImplementedError("Please implement this yourself.")

    def verifyOCRCode(self, ocrCode):
        """
        Verifies the given receipt.
        :param ocrCode: The receipt as OCR code string.
        :returns: The receipt object and the used algorithm class object.
        :throws: CertSerialInvalidException
        :throws: CertSerialMismatchException
        :throws: NoPublicKeyException
        :throws: InvalidSignatureException
        :throws: UnknownAlgorithmException
        :throws: SignatureSystemFailedException
        :throws: MalformedReceiptException
        :throws: UnsignedNullReceiptException
        """
        raise NotImplementedError("Please implement this yourself.")

    def verifyCSV(self, csv):
        """
        Verifies the given receipt.
        :param csv: The receipt as CSV string.
        :returns: The receipt object and the used algorithm class object.
        :throws: CertSerialInvalidException
        :throws: CertSerialMismatchException
        :throws: NoPublicKeyException
        :throws: InvalidSignatureException
        :throws: UnknownAlgorithmException
        :throws: SignatureSystemFailedException
        :throws: MalformedReceiptException
        :throws: UnsignedNullReceiptException
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
        if len(certSerial) <= 0:
            return CertSerialType.INVALID

        # for some reason the ref impl has a negative serial on some certs
        if certSerial[0] == '-' and '-' not in certSerial[1:]:
            certSerial = certSerial[1:]

        parts = certSerial.split('-')
        certSerial = parts[0]
        if len(parts) > 2:
            return CertSerialType.INVALID
        elif len(parts) == 2:
            if not parts[1].isalnum():
                return CertSerialType.INVALID

        if len(certSerial) == 11 and certSerial[0:2] == 'S:' and certSerial[2:].isdigit():
            return CertSerialType.TAX
        elif len(certSerial) >= 3 and len(certSerial) <= 16 and certSerial[0:2] == 'U:'  and certSerial[2:].isalnum() and certSerial[2:] == certSerial[2:].upper():
            return CertSerialType.UID
        elif len(certSerial) == 15 and certSerial[0:2] == 'G:' and certSerial[2:].isdigit():
            return CertSerialType.GLN
        else:
            try:
                int(certSerial, 16)
                return CertSerialType.SERIAL
            except ValueError as e:
                try:
                    int(certSerial, 10)
                    return CertSerialType.SERIAL
                except ValueError as f:
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

    def verify(self, rec, algorithmPrefix):
        if algorithmPrefix not in algorithms.ALGORITHMS:
            raise receipt.UnknownAlgorithmException(rec.receiptId)
        algorithm = algorithms.ALGORITHMS[algorithmPrefix]

        certSerialType = CertSerialType.getCertSerialType(rec.certSerial)
        if certSerialType == CertSerialType.INVALID:
            raise CertSerialInvalidException(rec.receiptId)

        pubKey = None
        if certSerialType == CertSerialType.SERIAL:
            if rec.zda == 'AT0':
                raise InvalidCertificateProviderException(rec.receiptId)

            serials = key_store.strSerialToKeyIds(rec.certSerial)
            if self.cert:
                certSerial = key_store.numSerialToKeyId(self.cert.serial)
                if not certSerial in serials:
                    raise CertSerialMismatchException(rec.receiptId)
                pubKey = self.cert.public_key()
            else:
                for serial in serials:
                    pubKey = self.keyStore.getKey(serial)
                    if pubKey:
                        break
        else:
            if rec.zda != 'AT0':
                raise InvalidCertificateProviderException(rec.receiptId)

            if self.cert:
                pubKey = self.cert.public_key()
            else:
                pubKey = self.keyStore.getKey(rec.certSerial)

        if rec.isSignedBroken():
            if not rec.isDummy() and not rec.isReversal() and rec.isNull():
                raise UnsignedNullReceiptException(rec.receiptId)
            raise SignatureSystemFailedException(rec.receiptId)

        if not pubKey:
            raise NoPublicKeyException(rec.receiptId)

        jwsString = rec.toJWSString(algorithmPrefix)
        if not algorithm.verify(jwsString, pubKey):
            raise InvalidSignatureException(rec.receiptId)

        return rec, algorithm

    def verifyJWS(self, jwsString):
        rec, algorithmPrefix = receipt.Receipt.fromJWSString(jwsString)

        return self.verify(rec, algorithmPrefix)

    def verifyBasicCode(self, basicCode):
        rec, algorithmPrefix = receipt.Receipt.fromBasicCode(basicCode)

        return self.verify(rec, algorithmPrefix)

    def verifyOCRCode(self, ocrCode):
        rec, algorithmPrefix = receipt.Receipt.fromOCRCode(ocrCode)

        return self.verify(rec, algorithmPrefix)

    def verifyCSV(self, csv):
        rec, algorithmPrefix = receipt.Receipt.fromCSV(csv)

        return self.verify(rec, algorithmPrefix)

def verifyURLHash(rec, algorithm, urlHash):
    """
    Verifies that the given URL hash matches the given receipt.
    :param rec: The signed receipt as receipt object.
    :param algorithm: The algorithm whose hash part is used.
    :param urlHash: The URL hash to verify.
    :returns: Nothing if the verification was successful.
    :throws: InvalidURLHashException if the URL hash does not match
    the receipt.
    """
    basicCode = rec.toBasicCode(algorithm.id())

    calcHash = base64.urlsafe_b64encode((algorithm.hash(basicCode)[0:8]
        )).decode("utf-8").replace('=', '')
    if calcHash != urlHash:
        if urlHash:
            raise InvalidURLHashException(urlHash)
        else:
            raise InvalidURLHashException(rec.receiptId)

def getAndVerifyReceiptURL(rv, url):
    basicCode = utils.getBasicCodeFromURL(url)
    urlHash = utils.getURLHashFromURL(url)
    rec, algorithm = rv.verifyBasicCode(basicCode)
    verifyURLHash(rec, algorithm, urlHash)

INPUT_FORMATS = {
        'jws': lambda rv, s: rv.verifyJWS(s),
        'qr': lambda rv, s: rv.verifyBasicCode(s),
        'ocr': lambda rv, s: rv.verifyOCRCode(s),
        'url': lambda rv, s: getAndVerifyReceiptURL(rv, s),
        'csv': lambda rv, s: rv.verifyCSV(s)
        }

if __name__ == "__main__":
    import gettext
    gettext.install('rktool', './lang', True)

    import configparser
    import sys

    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Usage: ./verify_receipt.py <format> <key store> [<receipt string>]")
        sys.exit(0)

    if sys.argv[1] not in INPUT_FORMATS:
        print(_("Input format must be one of %s.") % INPUT_FORMATS.keys())
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

    print(_("All receipts verified successfully."))
