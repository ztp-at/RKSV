#!/usr/bin/env python2.7

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
This module contains classes to verify receipts.
"""
from builtins import int
from builtins import range

import base64

from six import string_types

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
        self._initargs = (rec,)

class NoPublicKeyException(receipt.ReceiptException):
    """
    Indicates that no public key to verify the signature of the receipt could be
    found.
    """
    def __init__(self, rec):
        super(NoPublicKeyException, self).__init__(rec, _("No public key found."))
        self._initargs = (rec,)

class InvalidSignatureException(receipt.ReceiptException):
    """
    Indicates that the signature of the receipt is invalid.
    """
    def __init__(self, rec):
        super(InvalidSignatureException, self).__init__(rec, _("Invalid Signature."))
        self._initargs = (rec,)

class NonFatalReceiptException(receipt.ReceiptException):
    """
    Indicates an error with the given receipt that may be alright in the
    context of the complete DEP.
    """
    def __init__(self, rec, msg):
        super(NonFatalReceiptException, self).__init__(rec,
                _("{} This is probably fine.").format(msg))
        self._initargs = (rec, msg)

class SignatureSystemFailedException(NonFatalReceiptException):
    """
    Indicates that the signature system failed and that the receipt was not
    signed.
    """
    def __init__(self, rec):
        super(SignatureSystemFailedException, self).__init__(rec, _("Signature System failed."))
        self._initargs = (rec,)

class InvalidURLHashException(receipt.ReceiptException):
    """
    Indicates that the given URL hash does not match the URL hash computed
    from the receipt.
    """
    def __init__(self, rec):
        super(InvalidURLHashException, self).__init__(rec, _("Invalid URL hash."))
        self._initargs = (rec,)

class UnsignedNullReceiptException(NonFatalReceiptException):
    """
    Indicates that a non-dummy and non-reversal null receipt has not been
    signed.
    """
    def __init__(self, rec):
        super(UnsignedNullReceiptException, self).__init__(rec, _("Null receipt not signed."))
        self._initargs = (rec,)

class ReceiptVerifierI(object):
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
    def fromCert(cert):
        """
        Creates a new receipt verifier from a certificate object.
        :param cert: The certificate as an object.
        :return: The new receipt verifier.
        """
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

        pubKey = None
        if rec.zda == 'AT0':
            if self.cert:
                pubKey = self.cert.public_key()
            else:
                pubKey = self.keyStore.getKey(rec.certSerial)
        else:
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

def receiptGenerator(lines):
    for l in lines:
        yield l.strip()

def singleInputToGenerator(inp):
    if isinstance(inp, string_types):
        return receiptGenerator([inp])
    return receiptGenerator(inp)

INPUT_FORMATS = {
        'jws': lambda rv, inp: (singleInputToGenerator(inp), rv.verifyJWS),
        'qr': lambda rv, inp: (singleInputToGenerator(inp), rv.verifyBasicCode),
        'ocr': lambda rv, inp: (singleInputToGenerator(inp), rv.verifyOCRCode),
        'url': lambda rv, inp: (singleInputToGenerator(inp),
            lambda s: getAndVerifyReceiptURL(rv, s)),
        'csv': lambda rv, inp: (singleInputToGenerator(inp), rv.verifyCSV)
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
        recs, ver = INPUT_FORMATS[sys.argv[1]](rv, sys.argv[3])
    else:
        recs, ver = INPUT_FORMATS[sys.argv[1]](rv, sys.stdin)

    idx = 0
    fails = 0
    for r in recs:
        try:
            ver(r)
        except receipt.ReceiptException as e:
            fails += 1
            print(_("Line {: >3}: {}").format(idx, e))
        idx += 1

    print(_("{} of {} receipts verified successfully.").format(idx - fails, idx))
