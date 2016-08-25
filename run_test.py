#!/usr/bin/python3

from builtins import int

import base64
import datetime
import json
import os
import sys

import cashreg
import depexport
import key_store
import sigsys
import utils

def usage():
    print("Usage: ./run_test.py open <JSON test case spec> <cert 1 priv> <cert 1> [<cert 2 priv> <cert 2>]...")
    print("       ./run_test.py closed <JSON test case spec> <key 1 priv> <pub key 1> [<key 2 priv> <pub key 2>]...")
    sys.exit(0)

if __name__ == "__main__":
    import gettext
    gettext.install('rktool', './lang', True)

    if len(sys.argv) < 4 or len(sys.argv) % 2 != 1:
        usage()

    closed = False
    if sys.argv[1] == 'closed':
        closed = True
    elif sys.argv[1] != 'open':
        usage()

    tcJson = None
    with open(sys.argv[2]) as f:
        tcJson = json.loads(f.read())

    if len(sys.argv) != (tcJson['numberOfSignatureDevices'] * 2 + 3):
        print(_("I need keys and certificates for %d signature devices.") %
                tcJson['numberOfSignatureDevices'])
        sys.exit(0)

    baseDir = tcJson['simulationRunLabel']
    if not os.path.exists(baseDir):
        os.mkdir(baseDir)

    key = base64.b64decode(tcJson['base64AesKey'])

    register = cashreg.CashRegister(tcJson['cashBoxId'], None,
            int(0.0 * 100), key)

    keyStore = key_store.KeyStore()

    sigsBroken = list()
    sigsWorking = list()
    for i in range(tcJson['numberOfSignatureDevices']):
        serial = None
        with open(sys.argv[i * 2 + 1 + 3]) as f:
            cert = f.read()
            if closed:
                serial = "%s-K%d" % (tcJson['companyID'], i)
                keyStore.putPEMKey(serial, cert)
            else:
                keyStore.putPEMCert(cert)
                serial = key_store.numSerialToKeyId(utils.loadCert(cert).serial)

        sigB = sigsys.SignatureSystemBroken('AT0', serial)
        sigW = sigsys.SignatureSystemWorking('AT0', serial,
                sys.argv[i * 2 + 3])

        sigsBroken.append(sigB)
        sigsWorking.append(sigW)

    os.chdir(baseDir)

    receipts = list()
    for recI in tcJson['cashBoxInstructionList']:
        receiptId = recI['receiptIdentifier']
        dateTime = datetime.datetime.strptime(recI['dateToUse'],
                "%Y-%m-%dT%H:%M:%S")

        sumA = recI['simplifiedReceipt']['taxSetNormal']
        sumB = recI['simplifiedReceipt']['taxSetErmaessigt1']
        sumC = recI['simplifiedReceipt']['taxSetErmaessigt2']
        sumD = recI['simplifiedReceipt']['taxSetNull']
        sumE = recI['simplifiedReceipt']['taxSetBesonders']

        sig = None
        if recI['signatureDeviceDamaged']:
            sig = sigsBroken[recI['usedSignatureDevice']]
        else:
            sig = sigsWorking[recI['usedSignatureDevice']]

        dummy = False
        reversal = False
        if 'typeOfReceipt' in recI:
            if recI['typeOfReceipt'] == 'STORNO_BELEG':
                reversal = True
            if recI['typeOfReceipt'] == 'TRAINING_BELEG':
                dummy = True

        rec = register.receipt('R1', receiptId, dateTime, sumA, sumB, sumC,
                sumD, sumE, sig, dummy, reversal)
        receipts.append(rec)

    exporter = depexport.DEPExporter('R1', None)

    with open('dep-export.json', 'w') as f:
        f.write(exporter.export(receipts))

    with open('cryptographicMaterialContainer.json', 'w') as f:
        ksJson = keyStore.writeStoreToJson()
        ksJson['base64AESKey'] = tcJson['base64AesKey']
        f.write(json.dumps(ksJson, sort_keys=False, indent=2))
