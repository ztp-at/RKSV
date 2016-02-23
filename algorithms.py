import base64
import jwt
import jwt.algorithms
import struct

import utils

class AlgorithmI:
    def id(self):
        raise NotImplementedError("Please implement this yourself.")

    def jwsHeader(self):
        raise NotImplementedError("Please implement this yourself.")

    def chain(self, receipt, previousJwsString):
        raise NotImplementedError("Please implement this yourself.")

    def sign(self, jwsString, privKey):
        raise NotImplementedError("Please implement this yourself.")

    def verify(self, jwsString, cert):
        raise NotImplementedError("Please implement this yourself.")

    def encryptTurnoverCounter(self, receipt, turnoverCounter, key):
        raise NotImplementedError("Please implement this yourself.")

    def decryptTurnoverCounter(self, receipt, encTurnoverCounter, key):
        raise NotImplementedError("Please implement this yourself.")

class R1(AlgorithmI):
    def id(self):
        return "R1"

    def jwsHeader(self):
        return '{"alg":"ES256"}'

    def hash(self, data):
        return utils.sha256(data.encode("utf-8"))

    def chain(self, receipt, previousJwsString):
        chainingValue = None
        if previousJwsString:
            chainingValue = utils.sha256(previousJwsString.encode("utf-8"))
        else:
            chainingValue = utils.sha256(receipt.registerId.encode("utf-8"))
        return chainingValue[0:8]

    def sign(self, payload, privKey):
        algo = jwt.algorithms.get_default_algorithms()['ES256']

        alg = self.jwsHeader().encode("utf-8")
        alg = base64.urlsafe_b64encode(alg).replace(b'=', b'')

        payload = base64.urlsafe_b64encode(payload).replace(b'=', b'')

        key = algo.prepare_key(privKey)
        sig = algo.sign(alg + b'.' + payload, key)

        sig = base64.urlsafe_b64encode(sig).replace(b'=', b'')

        return sig

    def verify(self, jwsString, cert):
        pubKey = utils.loadCert(cert).public_key()
        payload = None
        try:
            payload = jwt.PyJWS().decode(jwsString, pubKey)
        except jwt.exceptions.DecodeError as e:
            pass

        if payload:
            return True
        return False

    def encryptTurnoverCounter(self, receipt, turnoverCounter, key):
        iv = utils.sha256(receipt.registerId.encode("utf-8")
                + receipt.receiptId.encode("utf-8"))[0:16]
        pt = struct.pack(">q", turnoverCounter)
        return utils.aes256ctr(iv, key, pt)

    def decryptTurnoverCounter(self, receipt, encTurnoverCounter, key):
        iv = utils.sha256(receipt.registerId.encode("utf-8")
                + receipt.receiptId.encode("utf-8"))[0:16]
        decCtr = utils.aes256ctr(iv, key, encTurnoverCounter)

        # TODO: we only support up to 8 byte long counters
        needed = 8 - len(decCtr)
        if decCtr[0] >= 128:
            decCtr = bytes([255] * needed) + decCtr
        else:
            decCtr = bytes([0] * needed) + decCtr

        return struct.unpack(">q", decCtr)[0]

ALGORITHMS = { 'R1': R1() }
