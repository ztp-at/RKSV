"""
This module abstracts an algorithm class used for creating and verifying
receipts. The available algorithms are stored in the ALGORITHMS dictionary which
is indexed by the algorithm codes specified in the regulation.
"""
import base64
import jwt
import jwt.algorithms
import struct

import utils

class AlgorithmI:
    """
    The base class for algorithms. It contains functions every algorithm must
    implement. Do not use this directly.
    """

    def id(self):
        """
        The algorithm's code as specified in the regulation.
        :return: Returns the algorithm code as a string.
        """
        raise NotImplementedError("Please implement this yourself.")

    def jwsHeader(self):
        """
        The header to use when signing a receipt with JWS.
        :return: Returns the header as a string.
        """
        raise NotImplementedError("Please implement this yourself.")

    def sigAlgo(self):
        """
        The JWS signature algorithm used.
        :return: Returns the JWS signature algorithm as a string.
        """
        raise NotImplementedError("Please implement this yourself.")

    def hash(self, data):
        """
        Hashes the given data with the hash algorithm specified for the
        algorithm class.
        :param data: The data to hash as a string.
        :return: The hash value as a byte list.
        """
        raise NotImplementedError("Please implement this yourself.")

    def chain(self, receipt, previousJwsString):
        """
        Creates the chaining value to incorporate into a new receipt according
        to the algorithm class specification.
        :param receipt: The current receipt object into which the chaining value
        has to be incorporated.
        :param previousJwsString: The previous receipt as JWS string.
        :return: The chaining value to incorporate into the receipt as byte
        list.
        """
        raise NotImplementedError("Please implement this yourself.")

    def sign(self, payload, privKey):
        """
        Signs the given payload with the private key and returns the signature.
        :param payload: The payload to sign as a string.
        :param privKey: The private key as a PEM formatted string.
        :return: The JWS encoded signature string.
        """
        raise NotImplementedError("Please implement this yourself.")

    def verify(self, jwsString, pubKey):
        """
        Verifies the given JWS signature with the public key.
        :param jwsString: The receipt as JWS string.
        :param pubKey: The public key to use in cryptography's own format.
        :return: True if the signature is valid, False otherwise.
        """
        raise NotImplementedError("Please implement this yourself.")

    def verifyKey(self, key):
        """
        Checks if the given key is valid for encrypting/decrypting the
        turnover counter.
        :param key: The key as a byte list.
        :return:  True if the key is valid, False otherwise.
        """
        raise NotImplementedError("Please implement this yourself.")

    def encryptTurnoverCounter(self, receipt, turnoverCounter, key):
        """
        Encrypts the given turnover counter for the given receipt with the key.
        :param receipt: The receipt object in which the encrypted turnover
        counter will be used.
        :param turnoverCounter: The turnover counter as an int.
        :param key: The key as a byte list.
        :return: The encrypted turnover counter as a byte list.
        """
        raise NotImplementedError("Please implement this yourself.")

    def decryptTurnoverCounter(self, receipt, encTurnoverCounter, key):
        """
        Decrypts the given turnover counter for the receipt with the key.
        :param receipt: The receipt object in which the encrypted turnover
        counter is located.
        :param encTurnoverCounter: The encrypted turnover counter as a byte
        list.
        :param key: The key as a byte list.
        :return: The turnover counter as an int.
        """
        raise NotImplementedError("Please implement this yourself.")

class R1(AlgorithmI):
    """
    This is the implementation of the \"R1\" algorithm.
    """
    def id(self):
        return "R1"

    def jwsHeader(self):
        return '{"alg":"%s"}' % self.sigAlgo()

    def sigAlgo(self):
        return "ES256"

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

        payload = base64.urlsafe_b64encode(payload.encode(
            "utf-8")).replace(b'=', b'')

        key = algo.prepare_key(privKey)
        sig = algo.sign(alg + b'.' + payload, key)

        sig = base64.urlsafe_b64encode(sig).replace(b'=', b'')

        return sig

    def verify(self, jwsString, pubKey):
        payload = None
        try:
            payload = jwt.PyJWS().decode(jwsString, pubKey)
        except jwt.exceptions.DecodeError as e:
            pass

        if payload:
            return True
        return False

    def verifyKey(self, key):
        if not isinstance(key, bytes):
            return False
        if len(key) != 32:
            return False
        return True

    def encryptTurnoverCounter(self, receipt, turnoverCounter, key):
        iv = utils.sha256(receipt.registerId.encode("utf-8")
                + receipt.receiptId.encode("utf-8"))[0:16]
        # TODO: We always use an 8 byte long counter.
        pt = struct.pack(">q", turnoverCounter)
        return utils.aes256ctr(iv, key, pt)

    def decryptTurnoverCounter(self, receipt, encTurnoverCounter, key):
        iv = utils.sha256(receipt.registerId.encode("utf-8")
                + receipt.receiptId.encode("utf-8"))[0:16]
        decCtr = utils.aes256ctr(iv, key, encTurnoverCounter)

        # TODO: We only support up to 8 byte long counters.
        needed = 8 - len(decCtr)
        if decCtr[0] >= 128:
            decCtr = bytearray([255] * needed) + bytearray(decCtr)
        else:
            decCtr = bytearray([0] * needed) + bytearray(decCtr)

        return struct.unpack(">q", decCtr)[0]

ALGORITHMS = { 'R1': R1() }
