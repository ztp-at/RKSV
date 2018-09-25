#!/usr/bin/env python2.7

###########################################################################
# Copyright 2017 ZT Prentner IT GmbH (www.ztp.at)
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

from __future__ import print_function
from builtins import int
from builtins import range

import gettext
gettext.install('rktool', './lang', True)

import datetime
import random
import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from librksv import depexport
from librksv import cashreg
from librksv import sigsys
from librksv import utils

def usage():
    print("Usage: ./demo.py <private key file> <cert file> <base64 AES key file> <number of receipts>")
    print("       ./demo.py <private key file> <public key file> <key ID> <base64 AES key file> <number of receipts>")
    print("       ./demo.py <base64 AES key file> <number of receipts>")
    sys.exit(0)

def receiptGen(register, sigsystem, num):
    # initial receipt
    yield (register.receipt('R1', "00000", datetime.datetime.now(), 0.0, 0.0,
        0.0, 0.0, 0.0, sigsystem), 'R1')

    # the rest
    for i in range(1, num):
        receiptId = "%05d" % i
        sumA = round(random.uniform(-1000, 1000), 2)
        sumB = round(random.uniform(-1000, 1000), 2)
        sumC = round(random.uniform(-1000, 1000), 2)
        sumD = round(random.uniform(-1000, 1000), 2)
        sumE = round(random.uniform(-1000, 1000), 2)
        dummy = random.uniform(0, 1) > 0.5
        reversal = random.uniform(0, 1) > 0.5
        receipt = register.receipt('R1', receiptId, datetime.datetime.now(),
                sumA, sumB, sumC, sumD, sumE, sigsystem, dummy, reversal)
        yield (receipt, 'R1')

if __name__ == "__main__":
    if len(sys.argv) < 3 or len(sys.argv) > 6:
        usage()

    cert = None
    sigsystem = None
    keyf = None
    num = 0
    if len(sys.argv) == 3:
        sigsystem = sigsys.SignatureSystemATrustMobile("u123456789",
                "123456789", "misc/A-Trust-Stamm.pem")
        keyf = sys.argv[1]
        num = int(sys.argv[2])
    elif len(sys.argv) == 5:
        priv = None
        with open(sys.argv[1]) as f:
            priv = f.read()
        serial = None
        with open(sys.argv[2]) as f:
            cert = utils.loadCert(f.read())
            serial = "%x" % abs(cert.serial_number)

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
        key = utils.loadB64Key(f.read().encode("utf-8"))

    register = cashreg.CashRegister("PIGGYBANK-007", None, int(0.0 * 100), key)

    rec_generator = receiptGen(register, sigsystem, num)
    exporter = depexport.JSONExporter.fromSingleGroup(rec_generator)

    for s in exporter.export():
        print(s, end='')
    print()
