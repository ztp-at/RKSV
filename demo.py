#!/usr/bin/python3

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

if __name__ == "__main__":
    if len(sys.argv) < 5 or len(sys.argv) > 6:
        print("Usage: ./demo.py <private key file> <cert file> <base64 AES key file> <number of receipts>")
        print("       ./demo.py <private key file> <public key file> <key ID> <base64 AES key file> <number of receipts>")
        sys.exit(0)

    priv = None
    cert = None
    keyf = None
    serial = None
    num = 0
    if len(sys.argv) == 5:
        priv = sys.argv[1]
        cert = sys.argv[2]
        keyf = sys.argv[3]
        num = int(sys.argv[4])
    else:
        priv = sys.argv[1]
        cert = sys.argv[2]
        serial = sys.argv[3]
        keyf = sys.argv[4]
        num = int(sys.argv[5])

    if num < 1:
        print("The number of receipts must be at least 1.")
        sys.exit(0)

    key = None
    with open(keyf) as f:
        key = base64.b64decode(f.read().encode("utf-8"))

    if not serial:
        with open(cert) as f:
            serial = "%x" % utils.loadCert(f.read()).serial

    register = cashreg.CashRegister("AT77", "PIGGYBANK-007", None, int(0.0 * 100), key)
    sigsystem = sigsys.SignatureSystemWorking(serial, priv)
    exporter = None
    if len(sys.argv) == 5:
        exporter = depexport.DEPExporter('R1', cert)
    else:
        exporter = depexport.DEPExporter('R1', None)

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
