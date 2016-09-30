"""
This module provides classes to work as signature systems.
"""
from builtins import int

import base64
import requests

class SignatureSystemI:
    """
    The base class for signature systems. It contains functions that every
    signature system must implement. Do not use this directly.
    """

    serial = None
    """
    The serial of the certificate the signature system uses.
    :return: The serial as a string.
    """

    zda = None
    """
    The ZDA ID of the signature provider.
    :return: The ZDA ID as a string.
    """

    def sign(self, data, algorithm):
        """
        Signs the given payload using the given algorithm.
        :param data: The data to be signed as a string.
        :param algorithm: The algorithm object used to perform the signature.
        :return: The signed data as JWS string.
        """
        raise NotImplementedError("Please implement this yourself.")

class SignatureSystemBroken(SignatureSystemI):
    """
    A broken signature system. It will \"sign\" all receipts with the standard
    broken message.
    """

    def __init__(self, zda, serial):
        """
        Creates a broken signature system.
        :param zda: The ZDA ID as a string.
        :param serial: The serial of the certificate, that would normally be
        used, as a string.
        """
        self.zda = zda
        self.serial = serial

    def sign(self, data, algorithm):
        head = algorithm.jwsHeader().encode("utf-8")
        data = data.encode("utf-8")
        sig = 'Sicherheitseinrichtung ausgefallen'.encode("utf-8")

        head = base64.urlsafe_b64encode(head).replace(b'=', b'')
        data = base64.urlsafe_b64encode(data).replace(b'=', b'')
        sig = base64.urlsafe_b64encode(sig).replace(b'=', b'')

        return (head + b'.' + data + b'.' + sig).decode('utf-8')

    def serial(self):
        return self.serial

    def zda(self):
        return self.zda

class SignatureSystemWorking(SignatureSystemI):
    """
    A working signature system. It will sign receipts.
    """

    def __init__(self, zda, serial, priv):
        """
        Creates a working signature system.
        :param zda: The ZDA ID as a string.
        :param serial: The serial of the certificate as a string.
        :param priv: The private key in PEM format.
        """
        self.zda = zda
        self.serial = serial
        self.secret = priv

    def sign(self, data, algorithm):
        head = algorithm.jwsHeader().encode("utf-8")
        head = base64.urlsafe_b64encode(head).replace(b'=', b'')

        sig = algorithm.sign(data, self.secret)

        data = data.encode("utf-8")
        data = base64.urlsafe_b64encode(data).replace(b'=', b'')

        return (head + b'.' + data + b'.' + sig).decode('utf-8')

    def serial(self):
        return self.serial

    def zda(self):
        return self.zda

class SignatureSystemATrustMobile(SignatureSystemI):
    """
    A signature system using the A-Trust Registrierkasse Mobile.
    """
    ATrustURL = 'https://hs-abnahme.a-trust.at/RegistrierkasseMobile/v2/'

    def __init__(self, username, password, certFile=True):
        """
        Creates a new signature system.
        :param username: The username for the A-Trust REST service as a string.
        :param password: The password for the A-Trust REST service as a string.
        :param certFile: A path to a PEM certificate file containing the root CA
        used to verify the servers SSL certificate, or True to use the system's
        CA store or False to disable verification.
        """
        self.username = username
        self.password = password
        self.certFile = certFile

        CertInfoEndpoint = '/%s/Certificate' % self.username
        r = requests.get(self.ATrustURL + CertInfoEndpoint, verify=certFile)
        r.raise_for_status()
        self.serial = r.json()['ZertifikatsseriennummerHex']
        self.algo = r.json()['algo']

        ZDAInfoEndpoint = '/%s/ZDA' % self.username
        r = requests.get(self.ATrustURL + ZDAInfoEndpoint, verify=certFile)
        r.raise_for_status()
        self.zda = r.json()['zdaid']

    def sign(self, data, algorithm):
        SignEndpoint = '/%s/Sign/JWS' % self.username

        if algorithm.sigAlgo() != self.algo:
            raise Exception(_("Selected algorithm not supported."))

        rdata = { 'password': self.password, 'jws_payload': data }
        try:
            r = requests.post(self.ATrustURL + SignEndpoint, json=rdata,
                    verify=self.certFile)
            r.raise_for_status()
            return r.json()['result']
        except requests.exceptions.RequestException as e:
            return SignatureSystemBroken(self.zda, self.serial).sign(data,
                    algorithm)
