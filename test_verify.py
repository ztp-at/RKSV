#!/usr/bin/env python2.7

###########################################################################
# Copyright 2017 ZT Prentner IT GmbH
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

"""
This module provides functions to read tests cases from a specification
and test the verification functions against them.
"""

from __future__ import print_function
from builtins import int
from builtins import range
from builtins import str

import base64
import enum
import re

import depparser
import key_store
import receipt
import verification_state
import verify

import run_test

class TestVerifyResult(enum.Enum):
    """
    An enum for the possible outcomes of a test case.
    """
    OK = 1
    FAIL = 2
    ERROR = 3

from sys import version_info
if version_info[0] < 3:
    import __builtin__
else:
    import builtins as __builtin__

def _testVerify(spec, deps, cc, parse=False, pool = None, nprocs = 1):
    """
    Runs a single test case against verify.verifyDEP() and returns the
    result and potentially an error message. In addition to the elements
    understood by run_test.runTest(), this function also understands the
    "expectedException" element, which indicates the name of the exception
    the verifyDEP() function is expected to throw, and the
    "exceptionReceipt" element, which indicates the receipt at which an
    exception is expected to occur. If "exceptionReceipt" is omitted, the
    expected exception may occur anywhere in the generated DEP. If
    "expectedException" is omitted, verifyDEP() must not throw any
    exception.
    :param spec: The test case specification as a dict structure.
    :param deps: A list of DEPs to verify.
    :param cc: The cryptographic material container containing the key
    material to verify the DEPs.
    :param parse: True if the DEP should be parsed with
    depparser.dictDEPParser first, false otherwise.
    :param pool: A pool of processes to pass along to verifyParsedDEP if
    parse is True.
    :param nprocs: The number of processes to expect/use in pool.
    :return: A TestVerifyResult indicating the result of the test and an
    error message. If the result is OK, the message is None.
    """
    expected_exception_type = _('no Exception')
    expected_exception_receipt = None
    expected_exception_msg = None
    expected_exception_msg_regex = None

    actual_exception_type = _('no Exception')
    actual_exception = None

    # Save the _() function.
    trans = __builtin__._ 

    try:
        expected_exception_type = spec.get('expectedException',
                _('no Exception'))
        expected_exception_receipt = spec.get('exceptionReceipt')
        expected_exception_msg = spec.get('exceptionMsg')
        expected_exception_msg_regex = spec.get('exceptionMsgRegex')
        if expected_exception_msg_regex is not None:
            expected_exception_msg_regex = re.compile(expected_exception_msg_regex)


        key = base64.b64decode(spec['base64AesKey'])
        ks = key_store.KeyStore.readStoreFromJson(cc)

        state = verification_state.ClusterState()
        depToRegisterIdx = list()
        nRegisters = 0
        for i in range(len(deps)):
            dep = deps[i]

            registerIdx = nRegisters
            partialDEP = dep.get('Fortgesetztes-DEP', False)

            if partialDEP:
                registerIdx = depToRegisterIdx[dep['Vorheriges-DEP']]
            else:
                nRegisters += 1

            expectedTurnover = dep.get('Umsatz-gesamt', None)

            depToRegisterIdx.append(registerIdx)

            if parse:
                prevJWS, crsOld, ids = state.getCashRegisterInfo(registerIdx)

                # Temporarily disable translations to make sure error
                # messages match.
                __builtin__._ = lambda x: x

                parser = depparser.DictDEPParser(dep, nprocs)
                state = verify.verifyParsedDEP(parser, ks, key, state,
                        registerIdx, pool, nprocs, 2)
                for chunk in parser.parse(0):
                    for recs, cert, chain in chunk:
                        crsOld.updateFromDEPGroup(recs, key)

                __builtin__._ = trans

                prevJWS, crsNew, ids = state.getCashRegisterInfo(registerIdx)
                if crsOld != crsNew:
                    return TestVerifyResult.FAIL, Exception(
                            _('State update without verification failed.'))
            else:
                # Temporarily disable translations to make sure error
                # messages match.
                __builtin__._ = lambda x: x
                state = verify.verifyDEP(dep, ks, key, state, registerIdx)
                __builtin__._ = trans

            if expectedTurnover:
                prevJWS, cashRegState, ids = state.getCashRegisterInfo(registerIdx)
                expectedTurnoverCounter = int(round(expectedTurnover * 100))
                if expectedTurnoverCounter != cashRegState.lastTurnoverCounter:
                    return TestVerifyResult.FAIL, Exception(
                            _('Expected {} in turnover counter but got {}.').format(
                                expectedTurnoverCounter,
                                cashRegState.lastTurnoverCounter))
    except (receipt.ReceiptException, verify.DEPException) as e:
        actual_exception = e
    except Exception as e:
        return TestVerifyResult.ERROR, e
    finally:
        # Restore the _() function.
        __builtin__._ = trans

    if actual_exception:
        actual_exception_type = type(actual_exception).__name__

    if actual_exception_type != expected_exception_type:
        return TestVerifyResult.FAIL, Exception(
                _('Expected "{}" but got "{}", message: "{}"').format(
                    expected_exception_type, actual_exception_type,
                    actual_exception))

    if actual_exception:
        if expected_exception_receipt and \
                actual_exception.receipt != expected_exception_receipt:
            return TestVerifyResult.FAIL, Exception(
                    _('Expected "{}" at receipt "{}" but it occured at "{}" instead').format(
                        expected_exception_type, expected_exception_receipt,
                        actual_exception.receipt))

        actual_exception_msg = '{}'.format(actual_exception)
        if expected_exception_msg is not None and \
                actual_exception_msg != expected_exception_msg:
            return TestVerifyResult.FAIL, Exception(
                    _('Expected message "{}" but got "{}" instead').format(
                        expected_exception_msg, actual_exception_msg))

        if expected_exception_msg_regex and \
                not expected_exception_msg_regex.match(actual_exception_msg):
            return TestVerifyResult.FAIL, Exception(
                    _('Expected message matching "{}" but got "{}" instead'
                        ).format(expected_exception_msg_regex.pattern,
                            actual_exception_msg))

    return TestVerifyResult.OK, None

def testVerify(spec, pub, priv, closed, pool = None, nprocs = 1):
    """
    Runs a single test case against verify.verifyDEP() and returns the
    result and potentially an error message. In addition to the elements
    understood by run_test.runTest(), this function also understands the
    "expectedException" element, which indicates the name of the exception
    the verifyDEP() function is expected to throw, and the
    "exceptionReceipt" element, which indicates the receipt at which an
    exception is expected to occur. If "exceptionReceipt" is omitted, the
    expected exception may occur anywhere in the generated DEP. If
    "expectedException" is omitted, verifyDEP() must not throw any
    exception.
    :param spec: The test case specification as a dict structure.
    :param pub: The public key or certificate. For a closed system a public
    key must be used, for an open system a certificate must be used.
    :param priv: The private key used to sign the generated receipts.
    :param closed: Indicates whether the system is a closed system (True) or
    an open system (False).
    :param pool: A pool of processes to pass along when using DEP parsing.
    :param nprocs: The number of processes to expect/use in pool.
    :return: A TestVerifyResult indicating the result of the test and an
    error message. If the result is OK, the message is None.
    """
    try:
        keymat = [(pub, priv)] * spec['numberOfSignatureDevices']
        deps, cc = run_test.runTest(spec, keymat, closed)
    except Exception as e:
        return TestVerifyResult.ERROR, e

    rN, mN = _testVerify(spec, deps, cc, False, pool, nprocs)
    rP, mP = _testVerify(spec, deps, cc, True, pool, nprocs)
    if rN == rP and str(mN) == str(mP):
        return rN, mN

    r = TestVerifyResult.FAIL
    if rN == TestVerifyResult.ERROR or rP == TestVerifyResult.ERROR:
        r = TestVerifyResult.ERROR
    return r, Exception(
            _('Result mismatch: without parsing {}:>{}<, with parsing {}:>{}<').format(
                    rN.name, mN, rP.name, mP))

def testVerifyMulti(specs, groupLabel, crt, pub, priv, tcDefaultSize,
        pool = None, nprocs = 1):
    """
    Runs all the given test cases against verify.verifyDEP. In addition to
    the elements understood by TestVerify(), this function also understands
    the "closedSystem" element in the root dictionary, which indicates
    whether the system is a closed system (True) or an open system (False).
    This function is a generator to facilitate more responsive output when
    used with many test cases.
    :param specs: A list or generator with test specifications as dict
    structures.
    :param groupLabel: A label to indicate which group the tests belong to
    as a string.
    :param crt: The certificate used to sign the generated receipts if an
    open system is used.
    :param pub: The public key used to sign the generated receipts if a
    closed system is used.
    :param priv: The private key belonging to the given certificate and
    public key.
    :param tcDefaultSize: The turnover counter size in bytes to use if no
    size is given in the test specification.
    :param pool: A pool of processes to pass along when using DEP parsing.
    :param nprocs: The number of processes to expect/use in pool.
    :yield: A tuple containing (in order) the test cases name, the group
    label, a boolean indicating whether the system is a closed (True) or an
    open (False) system, the used turnover counter size in bytes, the
    result of the test as a TestVerifyResult and the generated error
    message or None if no error occurred.
    """
    for s in specs:
        label = s.get('simulationRunLabel', 'Unknown')
        tc_size = s.get('turnoverCounterSize', tcDefaultSize)
        closed = s.get('closedSystem', False)
        if label == 'Unknown':
            result = TestVerifyResult.ERROR
            msg = _('No run label')
        else:
            pc = pub if closed else crt
            result, msg = testVerify(s, pc, priv, closed, pool, nprocs)
        yield (label, groupLabel, closed, tc_size, result, msg)

def printTestVerifyResult(label, groupLabel, closed, tcSize, result, msg):
    open_str = 'closed' if closed else 'open'
    print('{: <40}({: >6}, {: >2}, {: >8})...'.format(label, open_str,
        tcSize, groupLabel), end='')
    print('{:.>5}'.format(result.name))
    if msg:
        print(msg)

def printTestVerifySummary(results):
    nFails = sum(r[4] == TestVerifyResult.FAIL for r in results)
    nErrors = sum(r[4] == TestVerifyResult.ERROR for r in results)
    print(_('{} tests run, {} failed, {} errors').format(len(results), nFails, nErrors))

import json
import sys

def usage():
    print("Usage: ./test_verify.py open <JSON test case spec> <cert priv> <cert> [<turnover counter size>]")
    print("       ./test_verify.py closed <JSON test case spec> <key priv> <pub key> [<turnover counter size>]")
    print("       ./test_verify.py multi <key priv> <cert> <pub key> <turnover counter size 1>,... <group label> <JSON test case spec 1>...")
    sys.exit(3)

if __name__ == "__main__":
    def closed_or_usage(arg):
        if arg == 'closed':
            return True
        elif arg == 'open':
            return False
        usage()

    def tc_size_or_error(arg):
        turnoverCounterSize = int(arg)
        if turnoverCounterSize < 5 or turnoverCounterSize > 16:
            print(_("Turnover counter size needs to be between 5 and 16."))
            sys.exit(3)
        return turnoverCounterSize

    def arg_read_file(arg):
        with open(arg) as f:
            return f.read()

    def generate_specs(tcSizes, testCases):
        for s in tcSizes:
            for tc in testCases:
                tc['turnoverCounterSize'] = s

                if 'closedSystem' in tc:
                    spec = dict(tc)
                    yield spec
                    continue

                spec = dict(tc)
                spec['closedSystem'] = False
                yield spec

                spec = dict(tc)
                spec['closedSystem'] = True
                yield spec

    import gettext
    gettext.install('rktool', './lang', True)

    import multiprocessing
    # We should always test with multiprocessing to catch pickle issues.
    DEFAULT_NPROCS = 2

    if len(sys.argv) < 5:
        usage()

    if sys.argv[1] == 'multi':
        if len(sys.argv) < 8:
            usage()

        tcSizes = [ tc_size_or_error(s) for s in sys.argv[5].split(',') ]

        cert = arg_read_file(sys.argv[3])
        pub = arg_read_file(sys.argv[4])
        priv = arg_read_file(sys.argv[2])

        groupLabel = sys.argv[6]

        testCases = [ json.loads(arg_read_file(tc)) for tc in sys.argv[7:] ]

        specs = generate_specs(tcSizes, testCases)

        pool = multiprocessing.Pool(DEFAULT_NPROCS)
        results = testVerifyMulti(specs, groupLabel, cert, pub, priv, 8,
                pool, DEFAULT_NPROCS)

        resultList = list()
        try:
            for r in results:
                printTestVerifyResult(*r)
                resultList.append(r)
        finally:
            pool.terminate()
            pool.join()

        printTestVerifySummary(resultList)

        if any(r[4] == TestVerifyResult.ERROR for r in resultList):
            sys.exit(2)
        if any(r[4] == TestVerifyResult.FAIL for r in resultList):
            sys.exit(1)
        sys.exit(0)

    if len(sys.argv) > 6:
        usage()

    closed = closed_or_usage(sys.argv[1])

    tcJson = json.loads(arg_read_file(sys.argv[2]))

    if len(sys.argv) == 6:
        turnoverCounterSize = tc_size_or_error(sys.argv[5])
        tcJson['turnoverCounterSize'] = turnoverCounterSize

    pub = arg_read_file(sys.argv[4])
    priv = arg_read_file(sys.argv[3])

    test_name = tcJson['simulationRunLabel']
    tc_size = tcJson.get('turnoverCounterSize', 8)

    pool = multiprocessing.Pool(DEFAULT_NPROCS)
    try:
        result, msg = testVerify(tcJson, pub, priv, closed, pool,
                DEFAULT_NPROCS)
    finally:
        pool.terminate()
        pool.join()

    printTestVerifyResult(test_name, 'no Group', closed, tc_size, result, msg)

    if result == TestVerifyResult.ERROR:
        sys.exit(2)
    if result == TestVerifyResult.FAIL:
        sys.exit(1)
    sys.exit(0)
