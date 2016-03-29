"""
This module provides classes to work as signature systems.
"""
import base64

class SignatureSystemI:
    """
    The base class for signature systems. It contains functions that every
    signature system must implement. Do not use this directly.
    """

    def sign(self, data, algorithm):
        """
        Signs the given payload using the given algorithm.
        :param data: The data to be signed as a string.
        :param algorithm: The algorithm object used to perform the signature.
        :return: The signed data as JWS string.
        """
        raise NotImplementedError("Please implement this yourself.")

    def serial(self):
        """
        The serial of the certificate the signature system uses.
        :return: The serial as a string.
        """
        raise NotImplementedError("Please implement this yourself.")

class SignatureSystemBroken(SignatureSystemI):
    """
    A broken signature system. It will \"sign\" all receipts with the standard
    broken message.
    """

    def __init__(self, serial):
        """
        Creates a broken signature system.
        :param serial: The serial of the certificate, that would normally be
        used, as a string.
        """
        self.serial = serial

    def sign(self, data, algorithm):
        head = algorithm.jwsHeader().encode("utf-8")
        sig = 'Sicherheitseinrichtung ausgefallen'.encode("utf-8")

        head = base64.urlsafe_b64encode(head).replace(b'=', b'')
        data = base64.urlsafe_b64encode(data).replace(b'=', b'')
        sig = base64.urlsafe_b64encode(sig).replace(b'=', b'')

        return head + b'.' + data + b'.' + sig

    def serial(self):
        return self.serial

class SignatureSystemWorking(SignatureSystemI):
    """
    A working signature system. It will sign receipts.
    """

    def __init__(self, serial, privKeyFile):
        """
        Creates a working signature system.
        :param serial: The serial of the certificate as a string.
        :param privKeyFile: A file containing the private key in the PEM format.
        """
        self.serial = serial

        with open(privKeyFile) as f:
            self.secret = f.read()

    def sign(self, data, algorithm):
        head = algorithm.jwsHeader().encode("utf-8")
        head = base64.urlsafe_b64encode(head).replace(b'=', b'')

        sig = algorithm.sign(data, self.secret)

        data = base64.urlsafe_b64encode(data).replace(b'=', b'')

        return head + b'.' + data + b'.' + sig

    def serial(self):
        return self.serial
