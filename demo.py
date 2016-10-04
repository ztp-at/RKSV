#!/usr/bin/python3

from builtins import int

import base64
import datetime
import random
import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend

import depexport
import cashreg
import sigsys
import utils

def usage():
    print("Usage: ./demo.py <private key file> <cert file> <base64 AES key file> <number of receipts>")
    print("       ./demo.py <private key file> <public key file> <key ID> <base64 AES key file> <number of receipts>")
    print("       ./demo.py <base64 AES key file> <number of receipts>")
    sys.exit(0)

if __name__ == "__main__":
    import gettext
    gettext.install('rktool', './lang', True)

    if len(sys.argv) < 3 or len(sys.argv) > 6:
        usage()

    cert = None
    sigsystem = None
    keyf = None
    num = 0
    if len(sys.argv) == 3:
        sigsystem = sigsys.SignatureSystemATrustMobile("u123456789",
                "123456789", "A-Trust-Stamm.pem")
        keyf = sys.argv[1]
        num = int(sys.argv[2])
    elif len(sys.argv) == 5:
        priv = None
        with open(sys.argv[1]) as f:
            priv = f.read()
        cert = sys.argv[2]
        serial = None
        with open(cert) as f:
            serial = "%x" % abs(utils.loadCert(f.read()).serial)

        sigsystem = sigsys.SignatureSystemWorking("AT77", serial, priv)
        keyf = sys.argv[3]
        num = int(sys.argv[4])
    elif len(sys.argv) == 6:
        priv = None
        with open(sys.argv[1]) as f:
            priv = f.read()
        serial = sys.argv[3]

        sigsystem = sigsys.SignatureSystemWorking("AT0", serial, priv)
        keyf = sys.argv[4]
        num = int(sys.argv[5])
    else:
        usage()

    if num < 1:
        print(_("The number of receipts must be at least 1."))
        sys.exit(0)

    key = None
    with open(keyf) as f:
        key = base64.b64decode(f.read().encode("utf-8"))

    register = cashreg.CashRegister("PIGGYBANK-007", None, int(0.0 * 100), key)
    exporter = depexport.JSONExporter('R1', cert)

    receipts = [register.receipt('R1', "00000", datetime.datetime.now(), 0.0, 0.0, 0.0,
        0.0, 0.0, sigsystem)]
    for i in range(1, num):
        receiptId = "%05d" % i
        sumA = round(random.uniform(-1000, 1000), 2)
        sumB = round(random.uniform(-1000, 1000), 2)
        sumC = round(random.uniform(-1000, 1000), 2)
        sumD = round(random.uniform(-1000, 1000), 2)
        sumE = round(random.uniform(-1000, 1000), 2)
        dummy = random.uniform(0, 1) > 0.5
        reversal = random.uniform(0, 1) > 0.5
        receipt = register.receipt('R1', receiptId, datetime.datetime.now(), sumA, sumB,
                sumC, sumD, sumE, sigsystem, dummy, reversal)
        receipts.append(receipt)

    print(exporter.export(receipts))
