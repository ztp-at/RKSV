#!/usr/bin/python3

from builtins import int

import base64
import enum

import key_store
import receipt
import verify

import run_test

class TestVerifyResult(enum.Enum):
    OK = 1
    FAIL = 2
    ERROR = 3

def testVerify(spec, pub, priv, closed):
    expected_exception_type = 'no Exception'
    expected_exception_receipt = None

    actual_exception_type = 'no Exception'
    actual_exception = None

    try:
        expected_exception_type = spec.get('expectedException',
                'no Exception')
        expected_exception_receipt = spec.get('exceptionReceipt')

        keymat = [(pub, priv)] * spec['numberOfSignatureDevices']
        key = base64.b64decode(spec['base64AesKey'])

        dep, cc = run_test.runTest(spec, keymat, closed)
        ks = key_store.KeyStore.readStoreFromJson(cc)

        verify.verifyDEP(dep, ks, key)
    except (receipt.ReceiptException, verify.DEPException) as e:
        actual_exception = e
    except Exception as e:
        return TestVerifyResult.ERROR, e

    if actual_exception:
        actual_exception_type = type(actual_exception).__name__

    if actual_exception_type != expected_exception_type:
        return TestVerifyResult.FAIL, Exception(
                'Expected "{}" but got "{}", message: "{}"'.format(
                    expected_exception_type, actual_exception_type,
                    actual_exception))

    if actual_exception:
        if actual_exception.receipt != expected_exception_receipt:
            return TestVerifyResult.FAIL, Exception(
                    'Expected "{}" at receipt "{}" but it occured at "{}" instead'.format(
                        expected_exception_type, expected_exception_receipt,
                        actual_exception_receipt))

    return TestVerifyResult.OK, None

import json
import sys

def usage():
    print("Usage: ./test_verify.py open <JSON test case spec> <cert priv> <cert> [<turnover counter size>]")
    print("       ./test_verify.py closed <JSON test case spec> <key priv> <pub key> [<turnover counter size>]")
    sys.exit(0)

if __name__ == "__main__":
    import gettext
    gettext.install('rktool', './lang', True)

    if len(sys.argv) < 5 or len(sys.argv) > 6:
        usage()

    closed = False
    if sys.argv[1] == 'closed':
        closed = True
    elif sys.argv[1] != 'open':
        usage()

    tcJson = None
    with open(sys.argv[2]) as f:
        tcJson = json.loads(f.read())

    if len(sys.argv) == 6:
        turnoverCounterSize = int(sys.argv[5])
        if turnoverCounterSize < 5 or turnoverCounterSize > 16:
            print(_("Turnover counter size needs to be between 5 and 16."))
            sys.exit(0)
        tcJson['turnoverCounterSize'] = turnoverCounterSize

    pub = None
    priv = None
    with open(sys.argv[4]) as f:
        pub = f.read()
    with open(sys.argv[3]) as f:
        priv = f.read()

    test_name = tcJson['simulationRunLabel']
    open_str = 'closed' if closed else 'open'
    tc_size = tcJson.get('turnoverCounterSize', 8)

    print('{: <30}({: >6}, {: >2})...'.format(test_name, open_str,
        tc_size), end='')
    result, msg = testVerify(tcJson, pub, priv, closed)
    print('{:.>5}'.format(result.name))
    if msg:
        print(msg)
