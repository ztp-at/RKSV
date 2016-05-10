#!/usr/bin/python3

"""
This module provides an abstraction for a receipt and several basic conversion
functions.
"""
import base64
import datetime

from six import string_types

import algorithms

class ReceiptException(Exception):
    """
    An exception related to a receipt. Generally the message it prints contains
    the receipt in some string representation (usually JWS).
    """

    def __init__(self, receipt, message):
        super(ReceiptException, self).__init__("At receipt \"" + receipt + "\": " + message)

class MalformedReceiptException(ReceiptException):
    """
    Indicates that an attempt to parse a receipt from a string for failed
    because the string did not contain a valid receipt.
    """

    def __init__(self, receipt):
        super(MalformedReceiptException, self).__init__(receipt, "Malformed receipt.")

class UnknownAlgorithmException(ReceiptException):
    """
    Is thrown when a required algorithm is not available in
    algorithms.ALGORITHMS.
    """

    def __init__(self, receipt):
        super(UnknownAlgorithmException, self).__init__(receipt, "Unknown algorithm.")

class AlgorithmMismatchException(ReceiptException):
    """
    Indicates that an algorithm is not compatible with a receipt.
    """

    def __init__(self, receipt):
        super(AlgorithmMismatchException, self).__init__(receipt, "Algorithm mismatch.")

class InvalidKeyException(ReceiptException):
    """
    Indicates that a given key is invalid for a receipt.
    """

    def __init__(self, receipt):
        super(InvalidKeyException, self).__init__(receipt, "Invalid key.")

def restoreb64padding(data):
    """
    Restores the padding to a base64 string without padding. For internal use
    only.
    :param data: The base64 encoded string without padding.
    :return: The base64 encoded string with padding.
    """
    needed = 4 - len(data) % 4
    if needed:
        data += '=' * needed
    return data

class Receipt:
    """
    The basic receipt class. Contains methods to convert a receipt to and from
    various string formats.
    """

    def __init__(self, zda, registerId, receiptId, dateTime,
            sumA, sumB, sumC, sumD, sumE, encTurnoverCounter,
            certSerial, previousChain):
        """
        Creates a new receipt object.
        :param zda: The ZDA ID as a string.
        :param registerId: The ID of the register as a string.
        :param receiptId: The ID of the receipt as a string.
        :param dateTime: The receipt's timestamp as a datetime object.
        :param sumA: The first sum as a float.
        :param sumB: The second sum as a float.
        :param sumC: The third sum as a float.
        :param sumD: The fourth sum as a float.
        :param sumE: The fifth sum as a float.
        :param encTurnoverCounter: The encrypted turnover counter as a base64
        encoded string.
        :param certSerial: The certificate's serial or a key ID as a string.
        :param previousChain: The chaining value for the previous receipt as a
        base64 encoded string.
        """
        if not isinstance(receiptId, string_types):
            raise MalformedReceiptException("Unknown Receipt")
        if not isinstance(zda, string_types) or not isinstance(registerId, string_types):
            raise MalformedReceiptException(receiptId)
        if not isinstance(dateTime, datetime.datetime):
            raise MalformedReceiptException(receiptId)
        if not isinstance(sumA, float) or not isinstance(sumB, float) \
                or not isinstance(sumC, float) or not isinstance(sumD, float) \
                or not isinstance(sumE, float):
            raise MalformedReceiptException(receiptId)
        if not isinstance(encTurnoverCounter, string_types) \
                or not isinstance(certSerial, string_types) \
                or not isinstance(previousChain, string_types):
            raise MalformedReceiptException(receiptId)
        try:
            base64.b64decode(encTurnoverCounter.encode('utf-8'))
            base64.b64decode(previousChain.encode('utf-8'))
        except TypeError:
            raise MalformedReceiptException(receiptId)

        self.zda = zda
        self.header = None
        self.registerId = registerId
        self.receiptId = receiptId
        self.dateTime = dateTime
        self.sumA = sumA
        self.sumB = sumB
        self.sumC = sumC
        self.sumD = sumD
        self.sumE = sumE
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
        jwsSegs = jwsString.split('.')
        if len(jwsSegs) != 3:
            raise MalformedReceiptException(jwsString)
        header = None
        payload = None
        try:
            header = base64.urlsafe_b64decode(restoreb64padding(jwsSegs[0]).encode(
                "utf-8")).decode("utf-8")
            payload = base64.urlsafe_b64decode(restoreb64padding(jwsSegs[1])
                    .encode("utf-8")).decode("utf-8")
        except TypeError:
            raise MalformedReceiptException(jwsString)

        signature = jwsSegs[2]

        segments = payload.split('_')
        if len(segments) != 13 or len(segments[0]) != 0:
            raise MalformedReceiptException(jwsString)

        algorithmPrefixAndZda = segments[1].split('-')
        if len(algorithmPrefixAndZda) != 2:
            raise MalformedReceiptException(jwsString)
        algorithmPrefix = algorithmPrefixAndZda[0]
        zda = algorithmPrefixAndZda[1]

        if algorithmPrefix not in algorithms.ALGORITHMS:
            raise UnknownAlgorithmException(jwsString)
        if algorithms.ALGORITHMS[algorithmPrefix].jwsHeader() != header:
            raise AlgorithmMismatchException(jwsString)

        registerId = segments[2]
        receiptId = segments[3]

        dateTime = datetime.datetime.strptime(segments[4], "%Y-%m-%dT%H:%M:%S")
        if not dateTime:
            raise MalformedReceiptException(jwsString)

        sumA = float(segments[5].replace(',', '.'))
        sumB = float(segments[6].replace(',', '.'))
        sumC = float(segments[7].replace(',', '.'))
        sumD = float(segments[8].replace(',', '.'))
        sumE = float(segments[9].replace(',', '.'))

        turnoverCounter = segments[10]
        certSerial = segments[11]
        previousChain = segments[12]

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
            raise Exception("You need to sign the receipt first.")

        payload = self.toPayloadString(algorithmPrefix).encode("utf-8")
        payload = base64.urlsafe_b64encode(payload)
        payload = payload.replace(b'=', b'').decode("utf-8")

        jwsSegs = [base64.urlsafe_b64encode(self.header.encode("utf-8")).replace(b'=', b'')
                .decode("utf-8")]
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
        segments = [b'_' + algorithmPrefix.encode("utf-8") + b'-' + self.zda.encode("utf-8")]
        segments.append(self.registerId.encode("utf-8"))
        segments.append(self.receiptId.encode("utf-8"))
        segments.append(self.dateTime.strftime("%Y-%m-%dT%H:%M:%S").encode("utf-8"))
        # replacing '.' with ',' because reference does it too, still weird
        segments.append(("%.2f" % self.sumA).replace('.',',').encode("utf-8"))
        segments.append(("%.2f" % self.sumB).replace('.',',').encode("utf-8"))
        segments.append(("%.2f" % self.sumC).replace('.',',').encode("utf-8"))
        segments.append(("%.2f" % self.sumD).replace('.',',').encode("utf-8"))
        segments.append(("%.2f" % self.sumE).replace('.',',').encode("utf-8"))
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
        segments = basicCode.split('_')
        if len(segments) != 14 or len(segments[0]) != 0:
            raise MalformedReceiptException(basicCode)

        algorithmPrefixAndZda = segments[1].split('-')
        if len(algorithmPrefixAndZda) != 2:
            raise MalformedReceiptException(basicCode)
        algorithmPrefix = algorithmPrefixAndZda[0]
        zda = algorithmPrefixAndZda[1]

        if algorithmPrefix not in algorithms.ALGORITHMS:
            raise UnknownAlgorithmException(basicCode)
        header = algorithms.ALGORITHMS[algorithmPrefix].jwsHeader()

        registerId = segments[2]
        receiptId = segments[3]

        dateTime = datetime.datetime.strptime(segments[4], "%Y-%m-%dT%H:%M:%S")
        if not dateTime:
            raise MalformedReceiptException(basicCode)

        sumA = float(segments[5].replace(',', '.'))
        sumB = float(segments[6].replace(',', '.'))
        sumC = float(segments[7].replace(',', '.'))
        sumD = float(segments[8].replace(',', '.'))
        sumE = float(segments[9].replace(',', '.'))

        turnoverCounter = segments[10]
        certSerial = segments[11]
        previousChain = segments[12]

        signature = None
        try:
            signature = base64.b64decode(segments[13].encode("utf-8"))
        except TypeError:
            raise MalformedReceiptException(basicCode)
        signature = base64.urlsafe_b64encode(signature).replace(b'=', b'')
        signature = signature.decode("utf-8")

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
            raise Exception("You need to sign the receipt first.")

        payload = self.toPayloadString(algorithmPrefix)

        signature = restoreb64padding(self.signature).encode("utf-8")
        signature = base64.urlsafe_b64decode(signature)
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
        segments = ocrCode.split('_')
        if len(segments) != 14 or len(segments[0]) != 0:
            raise MalformedReceiptException(ocrCode)

        encTurnoverCounter = None
        previousChain = None
        signature = None
        try:
            encTurnoverCounter = base64.b32decode(segments[10])
            previousChain = base64.b32decode(segments[12])
            signature = base64.b32decode(segments[13])
        except TypeError:
            raise MalformedReceiptException(ocrCode)

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
            raise Exception("You need to sign the receipt first.")

        segments = [b'_' + algorithmPrefix.encode("utf-8") + b'-' + self.zda.encode("utf-8")]
        segments.append(self.registerId.encode("utf-8"))
        segments.append(self.receiptId.encode("utf-8"))
        segments.append(self.dateTime.strftime("%Y-%m-%dT%H:%M:%S").encode("utf-8"))
        # replacing '.' with ',' because reference does it too, still weird
        segments.append(("%.2f" % self.sumA).replace('.',',').encode("utf-8"))
        segments.append(("%.2f" % self.sumB).replace('.',',').encode("utf-8"))
        segments.append(("%.2f" % self.sumC).replace('.',',').encode("utf-8"))
        segments.append(("%.2f" % self.sumD).replace('.',',').encode("utf-8"))
        segments.append(("%.2f" % self.sumE).replace('.',',').encode("utf-8"))

        encTurnoverCounter = self.encTurnoverCounter.encode("utf-8")
        encTurnoverCounter = base64.b64decode(encTurnoverCounter)
        segments.append(base64.b32encode(encTurnoverCounter))

        segments.append(self.certSerial.encode("utf-8"))

        previousChain = self.previousChain.encode("utf-8")
        previousChain = base64.b64decode(previousChain)
        segments.append(base64.b32encode(previousChain))

        signature = restoreb64padding(self.signature).encode("utf-8")
        signature = base64.urlsafe_b64decode(signature)
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
            raise UnknownAlgorithmException(self.toJWSString(algorithmPrefix))
        algorithm = algorithms.ALGORITHMS[algorithmPrefix]

        return base64.urlsafe_b64encode((algorithm.hash(payload)[0:8])).decode("utf-8")

    @staticmethod
    def fromCSV(csv):
        """
        Creates a receipt object from a CSV string.
        :param csv: The CSV string to parse.
        :return: The new, signed receipt object.
        :throws: MalformedReceiptException
        :throws: UnknownAlgorithmException
        """
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
        :param signature: The signature as a base64 encoded string.
        """
        if not isinstance(header, string_types):
            raise MalformedReceiptException(self.receiptId)
        if not isinstance(signature, string_types):
            raise MalformedReceiptException(self.receiptId)
        try:
            base64.urlsafe_b64decode(restoreb64padding(signature).encode("utf-8"))
        except TypeError:
            raise MalformedReceiptException(self.receiptId)

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
            raise Exception("You need to sign the receipt first.")

        failStr = base64.urlsafe_b64encode(b'Sicherheitseinrichtung ausgefallen').replace(
                b'=', b'').decode("utf-8")
        return failStr == self.signature

    def isDummy(self):
        """
        Determines if this receipt is a dummy receipt.
        :return: True if the receipt is a dummy receipt, False otherwise.
        """
        decCtr = base64.b64decode(self.encTurnoverCounter.encode("utf-8"))
        return decCtr == b'TRA'

    def isReversal(self):
        """
        Determines if this receipt is a reversal.
        :return: True if the receipt is a reversal, False otherwise.
        """
        decCtr = base64.b64decode(self.encTurnoverCounter.encode("utf-8"))
        return decCtr == b'STO'

    def decryptTurnoverCounter(self, key, algorithm):
        """
        Decrypts the encrypted turnover counter using the given key and
        algorithm. The receipt must not be a dummy receipt or a reversal in
        order for this to work.
        :param key: The key to decrypt the counter as a byte list.
        :param algorithm: The algorithm to use as an algorithm object.
        :return: The decrypted turnover counter as int.
        """
        if self.isDummy():
            raise Exception("Can't decrypt turnover counter, this is a dummy receipt.")
        if self.isReversal():
            raise Exception("Can't decrypt turnover counter, this is a reversal receipt.")

        if not algorithm.verifyKey(key):
            raise InvalidKeyException(self.toJWSString(algorithm.id()))

        ct = base64.b64decode(self.encTurnoverCounter.encode("utf-8"))
        return algorithm.decryptTurnoverCounter(self, ct, key)

import sys

INPUT_FORMATS = {
        'jws': lambda s: Receipt.fromJWSString(s),
        'qr': lambda s: Receipt.fromBasicCode(s),
        'ocr': lambda s: Receipt.fromOCRCode(s),
        'csv': lambda s: Receipt.fromCSV(s)
        }

OUTPUT_FORMATS = {
        'jws': lambda r, p: r.toJWSString(p),
        'qr': lambda r, p: r.toBasicCode(p),
        'ocr': lambda r, p: r.toOCRCode(p),
        'url': lambda r, p: r.toURLHash(p),
        'csv': lambda r, p: r.toCSV(p)
        }

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: ./receipt.py <in format> <out format>")
        sys.exit(0)

    if sys.argv[1] not in INPUT_FORMATS:
        print("Input format must be one of %s." % INPUT_FORMATS.keys())
        sys.exit(0)

    if sys.argv[2] not in OUTPUT_FORMATS:
        print("Output format must be one of %s." % OUTPUT_FORMATS.keys())
        sys.exit(0)

    for l in sys.stdin:
        r, p = INPUT_FORMATS[sys.argv[1]](l.strip())
        s = OUTPUT_FORMATS[sys.argv[2]](r, p)
        print(s)
