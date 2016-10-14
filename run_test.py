#!/usr/bin/python3
"""
This module provides a function to generate a DEP and crypto container
according to a JSON test specification.
"""

from builtins import int

import base64
import datetime

import cashreg
import depexport
import key_store
import sigsys
import utils

def runTest(spec, keymat, closed=False, tcSize=None):
    """
    Creates a DEP and a crypto container structure according to the given
    test specification. In addition to the specification elements that the
    reference implementation uses, this function also understands the
    "decimalSerial", "turnoverCounterSize" and "includePublicKey" elements
    in the root dictionary and the "override" element in the dictionaries
    in the "cashBoxInstructionList" element.
    :param spec: The test specification as a dict structure.
    :param keymat: The key material as a list of tuples with the public key/
    certificate in the first element and the private key in the second
    element. The length of the list must be equal to the number of signature
    devices in the test specification. For a closed system public keys must
    be used, for an open system certificates must be used.
    :param closed: Indicates whether the system is a closed system (True) or
    an open system (False).
    :param tcSize: The size of the turnover counter in bytes. If this is
    omitted, the size is read from the specification. If the size is not
    set in the specification, 8 bytes are used.
    :return: A dict structure of the DEP and a dict structure of the crypto
    container.
    """
    if len(keymat) != spec['numberOfSignatureDevices']:
        raise Exception(_('Need key material for {} signature devices, got {} key pairs.').format(
        spec['numberOfSignatureDevices'], len(keymat)))

    key = base64.b64decode(spec['base64AesKey'])

    turnoverCounterSize = spec.get('turnoverCounterSize', 8)
    if tcSize:
        turnoverCounterSize = tcSize

    register = cashreg.CashRegister(spec['cashBoxId'], None,
            int(0.0 * 100), key, turnoverCounterSize)

    keyStore = key_store.KeyStore()

    zda = 'AT0' if closed else 'AT77'

    sigsBroken = list()
    sigsWorking = list()
    for i in range(spec['numberOfSignatureDevices']):
        serial = None
        if closed:
            serial = "%s-K%d" % (spec['companyID'], i)
            keyStore.putPEMKey(serial, keymat[i][0])
        else:
            keyStore.putPEMCert(keymat[i][0])
            certObj = utils.loadCert(keymat[i][0])
            numSerial = certObj.serial
            if spec.get('decimalSerial', False):
                serial = ('%d' % abs(numSerial))
            else:
                serial = key_store.numSerialToKeyId(numSerial)
            # Add raw public key too so that we can switch system type
            if spec.get('includePublicKey', False):
                kid = "%s-K%d" % (spec['companyID'], i)
                keyStore.putKey(kid, certObj.public_key(), None)

        sigB = sigsys.SignatureSystemBroken(zda, serial)
        sigW = sigsys.SignatureSystemWorking(zda, serial, keymat[i][1])

        sigsBroken.append(sigB)
        sigsWorking.append(sigW)

    override = dict()
    receipts = list()
    for recI in spec['cashBoxInstructionList']:
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

        override = recI.get('override', dict())

        rec = register.receipt('R1', receiptId, dateTime, sumA, sumB,
                sumC, sumD, sumE, sig, dummy, reversal, override)
        receipts.append(rec)

    algorithmPrefix = override.get('algorithmPrefix', 'R1')
    exporter = depexport.DEPExporter(algorithmPrefix, None)
    dep = exporter.export(receipts)

    ksJson = keyStore.writeStoreToJson()
    ksJson['base64AESKey'] = spec['base64AesKey']

    return dep, ksJson

import json
import os
import sys

def usage():
    print("Usage: ./run_test.py open <JSON test case spec> <cert 1 priv> <cert 1> [<cert 2 priv> <cert 2>]... [<turnover counter size>]")
    print("       ./run_test.py closed <JSON test case spec> <key 1 priv> <pub key 1> [<key 2 priv> <pub key 2>]... [<turnover counter size>]")
    sys.exit(0)

if __name__ == "__main__":
    import gettext
    gettext.install('rktool', './lang', True)

    if len(sys.argv) < 5:
        usage()

    closed = False
    if sys.argv[1] == 'closed':
        closed = True
    elif sys.argv[1] != 'open':
        usage()

    tcJson = None
    with open(sys.argv[2]) as f:
        tcJson = json.loads(f.read())

    if len(sys.argv) != (tcJson['numberOfSignatureDevices'] * 2 + 3
            ) and len(sys.argv) != (tcJson['numberOfSignatureDevices']
                    * 2 + 3 + 1):
        print(_("I need keys and certificates for %d signature devices.") %
                tcJson['numberOfSignatureDevices'])
        sys.exit(0)

    baseDir = tcJson['simulationRunLabel']
    if not os.path.exists(baseDir):
        os.mkdir(baseDir)

    turnoverCounterSize = None
    if len(sys.argv) % 2 != 1:
        turnoverCounterSize = int(sys.argv[-1])
        if turnoverCounterSize < 5 or turnoverCounterSize > 16:
            print(_("Turnover counter size needs to be between 5 and 16."))
            sys.exit(0)

    keymat = list()
    for i in range(tcJson['numberOfSignatureDevices']):
        pub = None
        priv = None
        with open(sys.argv[i * 2 + 1 + 3]) as f:
            pub = f.read()
        with open(sys.argv[i * 2 + 3]) as f:
            priv = f.read()
        keymat.append((pub, priv))

    dep, ks = runTest(tcJson, keymat, closed, turnoverCounterSize)

    os.chdir(baseDir)

    with open('dep-export.json', 'w') as f:
        f.write(json.dumps(dep, sort_keys=False, indent=2))

    with open('cryptographicMaterialContainer.json', 'w') as f:
        f.write(json.dumps(ks, sort_keys=False, indent=2))
