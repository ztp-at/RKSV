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
This module provides an abstraction for a receipt and several basic conversion
functions.
"""
from builtins import int
from builtins import range

import gettext
_ = gettext.translation('rktool', './lang', fallback=True).gettext

import base64
import binascii
import datetime
import enum
import re

from six import string_types

from . import algorithms
from . import utils

class ReceiptException(Exception):
    """
    An exception related to a receipt. Generally the message it prints contains
    the receipt in some string representation (usually JWS).
    """

    def __init__(self, receipt, message):
        super(ReceiptException, self).__init__(_("At receipt \"{0}\": {1}").format(receipt, message))
        self.receipt = receipt
        self._initargs = (receipt, message)

    def __reduce__(self):
        return (self.__class__, self._initargs)

class ReceiptParseException(ReceiptException):
    """
    Indicates that a receipt in some format could not be parsed into a
    receipt object.
    """

    def __init__(self, receipt, message):
        super(ReceiptParseException, self).__init__(receipt, message)
        self._initargs = (receipt, message)

class MalformedReceiptException(ReceiptParseException):
    """
    Indicates that an attempt to parse a receipt from a string for failed
    because the string did not contain a valid receipt.
    """

    def __init__(self, receipt, reason = None):
        if reason:
            msg = '{0} -- {1}'.format(_("Malformed receipt"), reason)
        else:
            msg = _("Malformed receipt.")
        super(MalformedReceiptException, self).__init__(receipt, msg)
        self._initargs = (receipt, reason)

class UnknownAlgorithmException(ReceiptParseException):
    """
    Is thrown when a required algorithm is not available in
    algorithms.ALGORITHMS.
    """

    def __init__(self, receipt):
        super(UnknownAlgorithmException, self).__init__(receipt, _("Unknown algorithm."))
        self._initargs = (receipt,)

class AlgorithmMismatchException(ReceiptParseException):
    """
    Indicates that an algorithm is not compatible with a receipt.
    """

    def __init__(self, receipt):
        super(AlgorithmMismatchException, self).__init__(receipt, _("Algorithm mismatch."))
        self._initargs = (receipt,)

class InvalidKeyException(ReceiptException):
    """
    Indicates that a given key is invalid for a receipt.
    """

    def __init__(self, receipt):
        super(InvalidKeyException, self).__init__(receipt, _("Invalid key."))
        self._initargs = (receipt,)

class CertSerialInvalidException(ReceiptException):
    """
    Indicates that the certificate serial in the receipt is malformed.
    """
    def __init__(self, rec):
        super(CertSerialInvalidException, self).__init__(rec, _("Certificate serial invalid."))
        self._initargs = (rec,)

class InvalidCertificateProviderException(ReceiptException):
    """
    Indicates that the given certificate provider (ZDA) is invalid.
    This usually means that AT0 was used in an open system or not used
    in a closed system.
    """
    def __init__(self, rec):
        super(InvalidCertificateProviderException, self).__init__(rec, _("Invalid certificate provider."))
        self._initargs = (rec,)

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

algRegex = re.compile(r'^R[1-9]\d*$')
zdaRegex = re.compile(r'^([A-Z][A-Z][1-9]\d*|AT0)$')

def _getSum(s, receiptId, reason):
    if not isinstance(s, string_types) or not s:
        raise MalformedReceiptException(receiptId, reason)
    sF = utils.getReceiptFloat(s)
    if sF is None:
        raise MalformedReceiptException(receiptId, reason)
    return sF

def _getTimestamp(dateTime, receiptId, reason):
    if not isinstance(dateTime, string_types) or not dateTime:
        raise MalformedReceiptException(receiptId, reason)
    try:
        dateTimeDT = datetime.datetime.strptime(dateTime, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        raise MalformedReceiptException(receiptId, reason)
    if not dateTimeDT:
        raise MalformedReceiptException(receiptId, reason)
    return dateTimeDT

def _getEmptyOrB64(b, receiptId, reason):
    if not isinstance(b, string_types):
        raise MalformedReceiptException(receiptId, reason)
    try:
        return utils.b64decode(b.encode('utf-8'))
    except (TypeError, binascii.Error):
        raise MalformedReceiptException(receiptId, reason)

class Receipt(object):
    """
    The basic receipt class. Contains methods to convert a receipt to and from
    various string formats.
    """

    def __init__(self, zda, registerId, receiptId, dateTime,
            sumA, sumB, sumC, sumD, sumE, encTurnoverCounter,
            certSerial, previousChain):
        """
        Creates a new receipt object. The dateTime and sum[A-E] attributes
        are stored as datetime and float objects respectively but their
        string representations are retained for the various to*() methods
        to ensure signatures remain valid after conversion.
        :param zda: The ZDA ID as a string.
        :param registerId: The ID of the register as a string.
        :param receiptId: The ID of the receipt as a string.
        :param dateTime: The receipt's timestamp as a string.
        :param sumA: The first sum as a string.
        :param sumB: The second sum as a string.
        :param sumC: The third sum as a string.
        :param sumD: The fourth sum as a string.
        :param sumE: The fifth sum as a string.
        :param encTurnoverCounter: The encrypted turnover counter as a base64
        encoded string.
        :param certSerial: The certificate's serial or a key ID as a string.
        :param previousChain: The chaining value for the previous receipt as a
        base64 encoded string.
        """
        if not isinstance(receiptId, string_types) or not receiptId:
            raise MalformedReceiptException(_("Unknown Receipt"),
                    _("Receipt ID \"{}\" invalid.").format(receiptId))
        if '_' in receiptId:
            raise MalformedReceiptException(receiptId,
                    _("Receipt ID \"{}\" invalid.").format(receiptId))

        if not isinstance(zda, string_types) or not zda \
                or zdaRegex.match(zda) is None:
            raise MalformedReceiptException(receiptId,
                    _("ZDA \"{}\" invalid.").format(zda))

        if not isinstance(registerId, string_types) or not registerId \
                or '_' in registerId:
            raise MalformedReceiptException(receiptId,
                    _("Register ID \"{}\" invalid.").format(registerId))

        dateTimeDT = _getTimestamp(dateTime, receiptId,
                    _("Timestamp \"{}\" invalid.").format(dateTime))

        sumAF = _getSum(sumA, receiptId,
                _('Sum tax normal \"{}\" invalid.').format(sumA))
        sumBF = _getSum(sumB, receiptId,
                _('Sum tax reduced 1 \"{}\" invalid.').format(sumB))
        sumCF = _getSum(sumC, receiptId,
                _('Sum tax reduced 2 \"{}\" invalid.').format(sumC))
        sumDF = _getSum(sumD, receiptId,
                _('Sum tax zero \"{}\" invalid.').format(sumD))
        sumEF = _getSum(sumE, receiptId,
                _('Sum tax special \"{}\" invalid.').format(sumE))

        # Due to how algorithm works encTurnoverCounter and previousChain
        # can both be the empty string when the receipt is created and not
        # parsed from a string.
        _getEmptyOrB64(encTurnoverCounter, receiptId,
                _('Encrypted turnover counter \"{}\" invalid.').format(
                    encTurnoverCounter))
        _getEmptyOrB64(previousChain, receiptId,
                _('Chaining value \"{}\" invalid.').format(previousChain))

        if not isinstance(certSerial, string_types) \
                or not certSerial:
            raise MalformedReceiptException(receiptId,
                    _('Certificate serial/Key ID \"{}\" invalid.').format(
                        certSerial))
        certSerialType = CertSerialType.getCertSerialType(certSerial)
        if certSerialType == CertSerialType.INVALID:
            raise CertSerialInvalidException(receiptId)
        if certSerialType == CertSerialType.SERIAL:
            if zda == 'AT0':
                raise InvalidCertificateProviderException(receiptId)
        else:
            if zda != 'AT0':
                raise InvalidCertificateProviderException(receiptId)

        self.zda = zda
        self.header = None
        self.registerId = registerId
        self.receiptId = receiptId
        self.dateTime = dateTimeDT
        self.dateTimeStr = dateTime
        self.sumA = sumAF
        self.sumAStr = sumA
        self.sumB = sumBF
        self.sumBStr = sumB
        self.sumC = sumCF
        self.sumCStr = sumC
        self.sumD = sumDF
        self.sumDStr = sumD
        self.sumE = sumEF
        self.sumEStr = sumE
        self.encTurnoverCounter = encTurnoverCounter
        self.certSerial = certSerial
        self.previousChain = previousChain
        self.signature = None
        self.signed = False

    @staticmethod
    def fromJWSString(jwsString):
        """
        Creates a receipt object from a JWS string.
        :param jwsString: The JWS string to parse.
        :return: The new, signed receipt object.
        :throws: MalformedReceiptException
        :throws: UnknownAlgorithmException
        :throws: AlgorithmMismatchException
        """
        if not isinstance(jwsString, string_types):
            raise MalformedReceiptException(jwsString, _('Invalid JWS.'))

        jwsSegs = jwsString.split('.')
        if len(jwsSegs) != 3:
            raise MalformedReceiptException(jwsString,
                    _('JWS does not contain exactly three segments.'))
        if jwsSegs[0].endswith('=') or jwsSegs[1].endswith('=') \
                or jwsSegs[2].endswith('='):
            raise MalformedReceiptException(jwsString,
                    _('Base 64 padding was used in JWS.'))

        header = None
        try:
            header = utils.urlsafe_b64decode(utils.restoreb64padding(
                jwsSegs[0]).encode("utf-8")).decode("utf-8")
        except (TypeError, binascii.Error, UnicodeDecodeError):
            raise MalformedReceiptException(jwsString,
                    _('Invalid JWS header.'))

        payload = None
        try:
            payload = utils.urlsafe_b64decode(utils.restoreb64padding(
                jwsSegs[1]).encode("utf-8")).decode("utf-8")
        except (TypeError, binascii.Error, UnicodeDecodeError):
            raise MalformedReceiptException(jwsString,
                    _('Invalid JWS payload.'))

        signature = jwsSegs[2]

        segments = payload.split('_')
        if len(segments) != 13 or len(segments[0]) != 0:
            raise MalformedReceiptException(jwsString,
                    _('JWS payload does not contain 12 elements.'))

        algorithmPrefixAndZda = segments[1].split('-')
        if len(algorithmPrefixAndZda) != 2:
            raise MalformedReceiptException(jwsString,
                    _('Payload does not contain algorithm and ZDA IDs.'))
        algorithmPrefix = algorithmPrefixAndZda[0]
        zda = algorithmPrefixAndZda[1]

        if algRegex.match(algorithmPrefix) is None:
            raise MalformedReceiptException(jwsString,
                    _('Algorithm ID \"{}\" invalid.').format(algorithmPrefix))
        if algorithmPrefix not in algorithms.ALGORITHMS:
            raise UnknownAlgorithmException(jwsString)
        if algorithms.ALGORITHMS[algorithmPrefix].jwsHeader() != header:
            raise AlgorithmMismatchException(jwsString)

        registerId = segments[2]
        receiptId = segments[3]
        dateTime = segments[4]
        sumA = segments[5]
        sumB = segments[6]
        sumC = segments[7]
        sumD = segments[8]
        sumE = segments[9]
        turnoverCounter = segments[10]
        certSerial = segments[11]
        previousChain = segments[12]

        # __init__ does not perform the latter two checks
        if not isinstance(turnoverCounter, string_types) \
                or not turnoverCounter.replace('=', ''):
            raise MalformedReceiptException(jwsString,
                    _('Encrypted turnover counter \"{}\" invalid.').format(
                        turnoverCounter))
        if not isinstance(previousChain, string_types) \
                or not previousChain.replace('=', ''):
            raise MalformedReceiptException(jwsString,
                    _('Chaining value \"{}\" invalid.').format(previousChain))

        receipt = Receipt(zda, registerId, receiptId, dateTime,
                sumA, sumB, sumC, sumD, sumE, turnoverCounter,
                certSerial, previousChain)
        receipt.sign(header, signature)

        return receipt, algorithmPrefix

    def toJWSString(self, algorithmPrefix):
        """
        Converts the receipt to a JWS string using the given algorithm class.
        The receipt has to be signed first.
        :param algorithmPrefix: The ID of the algorithm class used as a string.
        This should match the algorithm used to sign the receipt.
        :return: The receipt as a JWS string.
        """
        if not self.signed:
            raise Exception(_("You need to sign the receipt first."))

        payload = self.toPayloadString(algorithmPrefix).encode("utf-8")
        payload = base64.urlsafe_b64encode(payload)
        payload = payload.replace(b'=', b'').decode("utf-8")

        jwsSegs = [base64.urlsafe_b64encode(self.header.encode("utf-8")
            ).replace(b'=', b'').decode("utf-8")]
        jwsSegs.append(payload)
        jwsSegs.append(self.signature)

        return '.'.join(jwsSegs)

    def toPayloadString(self, algorithmPrefix):
        """
        Converts the receipt to a payload string that can be signed with JWS or
        used in the machine readable code.
        :param algorithmPrefix: The ID of the algorithm class used as a string.
        :return The receipt as a payload string.
        """
        segments = [b'_' + algorithmPrefix.encode("utf-8"
            ) + b'-' + self.zda.encode("utf-8")]
        segments.append(self.registerId.encode("utf-8"))
        segments.append(self.receiptId.encode("utf-8"))
        segments.append(self.dateTimeStr.encode("utf-8"))
        segments.append(self.sumAStr.encode("utf-8"))
        segments.append(self.sumBStr.encode("utf-8"))
        segments.append(self.sumCStr.encode("utf-8"))
        segments.append(self.sumDStr.encode("utf-8"))
        segments.append(self.sumEStr.encode("utf-8"))
        segments.append(self.encTurnoverCounter.encode("utf-8"))
        segments.append(self.certSerial.encode("utf-8"))
        segments.append(self.previousChain.encode("utf-8"))

        return b'_'.join(segments).decode("utf-8")

    @staticmethod
    def fromBasicCode(basicCode):
        """
        Creates a receipt object from a QR code string.
        :param basicCode: The QR code string to parse.
        :return: The new, signed receipt object.
        :throws: MalformedReceiptException
        :throws: UnknownAlgorithmException
        """
        if not isinstance(basicCode, string_types):
            raise MalformedReceiptException(basicCode,
                    _('Invalid machine-readable code.'))

        segments = basicCode.split('_')
        if len(segments) != 14 or len(segments[0]) != 0:
            raise MalformedReceiptException(basicCode,
                    _('Machine-readable code does not contain 13 elements.'))

        algorithmPrefixAndZda = segments[1].split('-')
        if len(algorithmPrefixAndZda) != 2:
            raise MalformedReceiptException(basicCode,
                    _('Machine-readable code does not contain algorithm and ZDA IDs.'))
        algorithmPrefix = algorithmPrefixAndZda[0]
        zda = algorithmPrefixAndZda[1]

        if algRegex.match(algorithmPrefix) is None:
            raise MalformedReceiptException(basicCode,
                    _('Algorithm ID \"{}\" invalid.').format(algorithmPrefix))
        if algorithmPrefix not in algorithms.ALGORITHMS:
            raise UnknownAlgorithmException(basicCode)
        header = algorithms.ALGORITHMS[algorithmPrefix].jwsHeader()

        registerId = segments[2]
        receiptId = segments[3]
        dateTime = segments[4]
        sumA = segments[5]
        sumB = segments[6]
        sumC = segments[7]
        sumD = segments[8]
        sumE = segments[9]
        turnoverCounter = segments[10]
        certSerial = segments[11]
        previousChain = segments[12]

        signature = None
        try:
            signature = utils.b64decode(segments[13].encode("utf-8"))
        except (TypeError, binascii.Error):
            raise MalformedReceiptException(basicCode,
                    _('Signature \"{}\" not Base 64 encoded.').format(segments[13]))
        signature = base64.urlsafe_b64encode(signature).replace(b'=', b'')
        signature = signature.decode("utf-8")

        # __init__ does not perform the latter two checks
        if not isinstance(turnoverCounter, string_types) \
                or not turnoverCounter.replace('=', ''):
            raise MalformedReceiptException(basicCode,
                    _('Encrypted turnover counter \"{}\" invalid.').format(
                        turnoverCounter))
        if not isinstance(previousChain, string_types) \
                or not previousChain.replace('=', ''):
            raise MalformedReceiptException(basicCode,
                    _('Chaining value \"{}\" invalid.').format(previousChain))

        receipt = Receipt(zda, registerId, receiptId, dateTime,
                sumA, sumB, sumC, sumD, sumE, turnoverCounter,
                certSerial, previousChain)
        receipt.sign(header, signature)

        return receipt, algorithmPrefix

    def toBasicCode(self, algorithmPrefix):
        """
        Converts the receipt to a QR code string.
        :param algorithmPrefix: The ID of the algorithm class used as a string.
        :return The receipt as a QR code string.
        """
        if not self.signed:
            raise Exception(_("You need to sign the receipt first."))

        payload = self.toPayloadString(algorithmPrefix)

        signature = utils.restoreb64padding(
                self.signature).encode("utf-8")
        signature = utils.urlsafe_b64decode(signature)
        signature = base64.b64encode(signature).decode("utf-8")

        return payload + '_' + signature

    @staticmethod
    def fromOCRCode(ocrCode):
        """
        Creates a receipt object from a OCR code string.
        :param ocrCode: The OCR code string to parse.
        :return: The new, signed receipt object.
        :throws: MalformedReceiptException
        :throws: UnknownAlgorithmException
        """
        if not isinstance(ocrCode, string_types):
            raise MalformedReceiptException(ocrCode,
                    _('Invalid OCR code.'))

        segments = ocrCode.split('_')
        if len(segments) != 14 or len(segments[0]) != 0:
            raise MalformedReceiptException(ocrCode,
                    _('OCR code does not contain 13 elements.'))

        encTurnoverCounter = None
        try:
            encTurnoverCounter = utils.b32decode(segments[10])
        except (TypeError, binascii.Error):
            raise MalformedReceiptException(ocrCode,
                    _('Encrypted turnover counter \"{}\" not Base 32 encoded.'
                        ).format(segments[10]))

        previousChain = None
        try:
            previousChain = utils.b32decode(segments[12])
        except (TypeError, binascii.Error):
            raise MalformedReceiptException(ocrCode,
                    _('Chaining value \"{}\" not Base 32 encoded.'
                        ).format(segments[12]))

        signature = None
        try:
            signature = utils.b32decode(segments[13])
        except (TypeError, binascii.Error):
            raise MalformedReceiptException(ocrCode,
                    _('Signature \"{}\" not Base 32 encoded.'
                        ).format(segments[13]))

        encTurnoverCounter = base64.b64encode(encTurnoverCounter)
        segments[10] = encTurnoverCounter.decode('utf-8')

        previousChain = base64.b64encode(previousChain)
        segments[12] = previousChain.decode('utf-8')

        signature = base64.b64encode(signature)
        segments[13] = signature.decode('utf-8')

        return Receipt.fromBasicCode('_'.join(segments))

    def toOCRCode(self, algorithmPrefix):
        """
        Converts the receipt to an OCR code string.
        :param algorithmPrefix: The ID of the algorithm class used as a string.
        :return The receipt as an OCR code string.
        """
        if not self.signed:
            raise Exception(_("You need to sign the receipt first."))

        segments = [b'_' + algorithmPrefix.encode("utf-8") + b'-' + self.zda.encode("utf-8")]
        segments.append(self.registerId.encode("utf-8"))
        segments.append(self.receiptId.encode("utf-8"))
        segments.append(self.dateTimeStr.encode("utf-8"))
        segments.append(self.sumAStr.encode("utf-8"))
        segments.append(self.sumBStr.encode("utf-8"))
        segments.append(self.sumCStr.encode("utf-8"))
        segments.append(self.sumDStr.encode("utf-8"))
        segments.append(self.sumEStr.encode("utf-8"))

        encTurnoverCounter = self.encTurnoverCounter.encode("utf-8")
        encTurnoverCounter = utils.b64decode(encTurnoverCounter)
        segments.append(base64.b32encode(encTurnoverCounter))

        segments.append(self.certSerial.encode("utf-8"))

        previousChain = self.previousChain.encode("utf-8")
        previousChain = utils.b64decode(previousChain)
        segments.append(base64.b32encode(previousChain))

        signature = utils.restoreb64padding(
                self.signature).encode("utf-8")
        signature = utils.urlsafe_b64decode(signature)
        segments.append(base64.b32encode(signature))

        return b'_'.join(segments).decode("utf-8")

    def toURLHash(self, algorithmPrefix):
        """
        Converts the receipt to a hash value to be used in URL verification.
        :param algorithmPrefix: The ID of the algorithm class used as a string.
        :return The receipt hash.
        :throws: UnknownAlgorithmException
        """
        payload = self.toBasicCode(algorithmPrefix)

        if algorithmPrefix not in algorithms.ALGORITHMS:
            raise UnknownAlgorithmException(self.receiptId)
        algorithm = algorithms.ALGORITHMS[algorithmPrefix]

        return base64.urlsafe_b64encode((algorithm.hash(payload)[0:8]
            )).decode("utf-8").replace('=', '')

    @staticmethod
    def fromCSV(csv):
        """
        Creates a receipt object from a CSV string.
        :param csv: The CSV string to parse.
        :return: The new, signed receipt object.
        :throws: MalformedReceiptException
        :throws: UnknownAlgorithmException
        """
        if not isinstance(csv, string_types):
            raise MalformedReceiptException(csv,
                    _('Invalid CSV.'))

        segs = [ s.strip() for s in csv.split(';') ]
        return Receipt.fromBasicCode('_' + ('_'.join(segs)))

    def toCSV(self, algorithmPrefix):
        """
        Converts the receipt to a CSV string.
        :param algorithmPrefix: The ID of the algorithm class used as a string.
        :return The receipt as a CSV string.
        """
        return self.toBasicCode(algorithmPrefix)[1:].replace('_', ';')

    def sign(self, header, signature):
        """
        Signs the receipt with the given signature and JWS header.
        :param header: The JWS header as a string.
        :param signature: The signature as an urlsafe base64 encoded string
        without padding.
        """
        if not isinstance(header, string_types):
            raise MalformedReceiptException(self.receiptId,
                    _('JWS header \"{}\" invalid.').format(header))

        if not isinstance(signature, string_types):
            raise MalformedReceiptException(self.receiptId,
                    _('Signature \"{}\" invalid.').format(signature))
        if signature.endswith('='):
            raise MalformedReceiptException(self.receiptId,
                    _('Signature \"{}\" uses padding.').format(signature))
        try:
            utils.urlsafe_b64decode(utils.restoreb64padding(
                signature).encode("utf-8"))
        except (TypeError, binascii.Error):
            raise MalformedReceiptException(self.receiptId,
                    _('Signature \"{}\" not Base 64 URL encoded.').format(signature))

        self.header = header
        self.signature = signature
        self.signed = True

    def isSignedBroken(self):
        """
        Determines if the signature system was inoperative when the receipt was
        signed. The receipt must be signed first.
        :return: True if the signature system was broken, False otherwise.
        """
        if not self.signed:
            raise Exception(_("You need to sign the receipt first."))

        failStr = base64.urlsafe_b64encode(b'Sicherheitseinrichtung ausgefallen').replace(
                b'=', b'').decode("utf-8")
        return failStr == self.signature

    def isDummy(self):
        """
        Determines if this receipt is a dummy receipt.
        :return: True if the receipt is a dummy receipt, False otherwise.
        """
        decCtr = utils.b64decode(self.encTurnoverCounter.encode("utf-8"))
        return decCtr == b'TRA'

    def isReversal(self):
        """
        Determines if this receipt is a reversal.
        :return: True if the receipt is a reversal, False otherwise.
        """
        decCtr = utils.b64decode(self.encTurnoverCounter.encode("utf-8"))
        return decCtr == b'STO'

    def isNull(self):
        """
        Determines if this receipt has zero turnover.
        :return: True if the receipt has zero turnover, False otherwise.
        """
        return self.sumA == 0.0 and self.sumB == 0.0 and self.sumC == 0.0 and self.sumD == 0.0 and self.sumE == 0.0

    def decryptTurnoverCounter(self, key, algorithm):
        """
        Decrypts the encrypted turnover counter using the given key and
        algorithm. The receipt must not be a dummy receipt or a reversal in
        order for this to work.
        :param key: The key to decrypt the counter as a byte list.
        :param algorithm: The algorithm to use as an algorithm object.
        :return: The decrypted turnover counter as int.
        :throws: InvalidKeyException
        """
        if self.isDummy():
            raise Exception(_("Can't decrypt turnover counter, this is a dummy receipt."))
        if self.isReversal():
            raise Exception(_("Can't decrypt turnover counter, this is a reversal receipt."))

        if not algorithm.verifyKey(key):
            raise InvalidKeyException(self.receiptId)

        ct = utils.b64decode(self.encTurnoverCounter.encode("utf-8"))
        return algorithm.decryptTurnoverCounter(self, ct, key)
