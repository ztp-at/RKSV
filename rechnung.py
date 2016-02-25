import base64
import datetime

class ReceiptException(Exception):
    def __init__(self, receipt, message):
        super(ReceiptException, self).__init__("At receipt \"" + receipt + "\": " + message)

class MalformedReceiptException(ReceiptException):
    def __init__(self, receipt):
        super(MalformedReceiptException, self).__init__(receipt, "Malformed receipt.")

def restoreb64padding(data):
    needed = 4 - len(data) % 4
    if needed:
        data += '=' * needed
    return data

class Rechnung:
    def __init__(self, zda, registerId, receiptId, dateTime,
            sumA, sumB, sumC, sumD, sumE, encTurnoverCounter,
            certSerial, previousChain):
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
        jwsSegs = jwsString.split('.')
        if len(jwsSegs) != 3:
            raise MalformedReceiptException(jwsString)
        header = jwsSegs[0]
        payload = base64.urlsafe_b64decode(restoreb64padding(jwsSegs[1]).encode("utf-8"))
        signature = jwsSegs[2]

        segments = payload.split(b'_')
        if len(segments) != 13 or len(segments[0]) != 0:
            raise MalformedReceiptException(jwsString)

        algorithmPrefixAndZda = segments[1].decode("utf-8").split('-')
        if len(algorithmPrefixAndZda) != 2:
            raise MalformedReceiptException(jwsString)
        algorithmPrefix = algorithmPrefixAndZda[0]
        zda = algorithmPrefixAndZda[1]

        registerId = segments[2].decode("utf-8")
        receiptId = segments[3].decode("utf-8")

        dateTime = datetime.datetime.strptime(segments[4].decode("utf-8"), "%Y-%m-%dT%H:%M:%S")
        if not dateTime:
            raise MalformedReceiptException(jwsString)

        sumA = float(segments[5].replace(b',', b'.'))
        sumB = float(segments[6].replace(b',', b'.'))
        sumC = float(segments[7].replace(b',', b'.'))
        sumD = float(segments[8].replace(b',', b'.'))
        sumE = float(segments[9].replace(b',', b'.'))

        turnoverCounter = segments[10].decode("utf-8")
        certSerial = segments[11].decode("utf-8")
        previousChain = segments[12].decode("utf-8")

        receipt = Rechnung(zda, registerId, receiptId, dateTime,
                sumA, sumB, sumC, sumD, sumE, turnoverCounter,
                certSerial, previousChain)
        receipt.sign(header, signature)

        return receipt, algorithmPrefix

    def toJWSString(self, algorithmPrefix):
        if not self.signed:
            raise Exception("You need to sign the receipt first.")

        payload = self.toPayloadString(algorithmPrefix).encode("utf-8")
        payload = base64.urlsafe_b64encode(payload)
        payload = payload.replace(b'=', b'').decode("utf-8")

        jwsSegs = [self.header]
        jwsSegs.append(payload)
        jwsSegs.append(self.signature)

        return '.'.join(jwsSegs)

    def toPayloadString(self, algorithmPrefix):
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

    def toBasicCode(self, algorithmPrefix):
        if not self.signed:
            raise Exception("You need to sign the receipt first.")

        payload = self.toPayloadString(algorithmPrefix)
        signature = restoreb64padding(self.signature).encode("utf-8")
        signature = base64.urlsafe_b64decode(signature)
        signature = base64.b64encode(signature).decode("utf-8")

        return payload + '_' + signature

    def toOCRCode(self, algorithmPrefix):
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
        segments.append(base64.b32encode(encTurnoverCounter))

        segments.append(self.certSerial.encode("utf-8"))

        previousChain = self.previousChain.encode("utf-8")
        segments.append(base64.b32encode(previousChain))

        signature = restoreb64padding(self.signature).encode("utf-8")
        signature = base64.urlsafe_b64decode(signature)
        segments.append(base64.b32encode(signature))

        return b'_'.join(segments).decode("utf-8")

    def toURLHash(self, algorithmPrefix, algorithm):
        payload = self.toBasicCode(algorithmPrefix)
        return base64.urlsafe_b64encode((algorithm.hash(payload)[0:8])).decode("utf-8")

    def sign(self, header, signature):
        self.header = header
        self.signature = signature
        self.signed = True

    def isSignedBroken(self):
        if not self.signed:
            raise Exception("You need to sign the receipt first.")

        failStr = base64.urlsafe_b64encode(b'Sicherheitseinrichtung ausgefallen').replace(
                b'=', b'').decode("utf-8")
        return failStr == self.signature

    def isDummy(self):
        decCtr = base64.b64decode(self.encTurnoverCounter.encode("utf-8"))
        return decCtr == b'TRA'

    def isReversal(self):
        decCtr = base64.b64decode(self.encTurnoverCounter.encode("utf-8"))
        return decCtr == b'STO'

    def decryptTurnoverCounter(self, key, algorithm):
        if self.isDummy():
            raise Exception("Can't decrypt turnover counter, this is a dummy receipt.")
        if self.isReversal():
            raise Exception("Can't decrypt turnover counter, this is a reversal receipt.")

        ct = base64.b64decode(self.encTurnoverCounter.encode("utf-8"))
        return algorithm.decryptTurnoverCounter(self, ct, key)
