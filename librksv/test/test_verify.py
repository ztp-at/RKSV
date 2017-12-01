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

from ..gettext_helper import _

import enum
import json
import random
import re
import sys
import tempfile

from .. import depparser
from .. import key_store
from .. import receipt
from .. import utils
from .. import verification_state
from .. import verify
from .. import verify_receipt

from .. import run_test

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

# FIXME: WARNING: looking up the exception class like this almost certainly
# allows for arbitrary code execution, do NOT use this outside of the test
# framework or in cases where you don't trust your test specs 100%, it is
# also broken in several other ways (for example when exceptions in different
# modules have identical names or when the given name is not an exception)
_librksvModuleRegex = re.compile(r'librksv.[A-Za-z0-9_]+$')
def _find_exception_class(excName):
    for name, mod in sys.modules.items():
        if not _librksvModuleRegex.search(name):
            continue

        excType = getattr(mod, excName, None)
        if excType:
            return excType

    return None

def _testVerify(spec, deps, cc, parse, proxy):
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
    :param proxy: An object implementing RKSVVerificationProxyI. This will
    be used to do the actual verification if parse is True.
    :return: A TestVerifyResult indicating the result of the test and an
    error message. If the result is OK, the message is None.
    """
    expected_exception_type = _('no Exception')
    expected_exception_receipt = None
    expected_exception_msg = None
    expected_exception_msg_regex = None

    actual_exception_type = _('no Exception')
    actual_exception = None

    try:
        expected_exception_type = spec.get('expectedException',
                _('no Exception'))
        expected_exception_receipt = spec.get('exceptionReceipt')
        expected_exception_msg = spec.get('exceptionMsg')
        expected_exception_msg_regex = spec.get('exceptionMsgRegex')
        if expected_exception_msg_regex is not None:
            expected_exception_msg_regex = re.compile(expected_exception_msg_regex)


        key = utils.loadB64Key(spec['base64AesKey'].encode('utf-8'))
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

                # We use text mode for the tempfile because otherwise
                # json.dump() fails on Python 3 and we'd have to use dumps()
                # and then encode the string before writing.
                with tempfile.TemporaryFile(mode='w+', suffix='.json',
                        prefix='rksv_test_dep_') as tmpf:
                    json.dump(dep, tmpf)
                    tmpf.seek(0)

                    # Pick a random chunk size.
                    nrecs = depparser.totalRecsInDictDEP(dep)
                    randCs = max(2, random.randint(0, nrecs - 1))

                    state = proxy.verify(tmpf, ks, key, state, registerIdx, randCs)

                    recids = set(ids)
                    tmpf.seek(0)
                    parser = depparser.FileDEPParser(tmpf)
                    for chunk in parser.parse(0):
                        for recs, cert, chain in chunk:
                            crsOld.updateFromDEPGroup(recs, key)
                            for r in recs:
                                rs = depparser.expandDEPReceipt(r)
                                ro = receipt.Receipt.fromJWSString(rs)[0]
                                recids.add(ro.receiptId)

                    if nrecs < 10:
                        chunksizes = list(range(1, nrecs + 1)) + [nrecs * 2]
                    else:
                        chunksizes = [1, randCs, nrecs, nrecs * 2]
                    dictParser = depparser.DictDEPParser(dep)
                    for i in chunksizes:
                        for cA, cB in zip(dictParser.parse(i), parser.parse(i)):
                            if cA != cB:
                                return TestVerifyResult.FAIL, Exception(
                                        _('Incremental and dict parser yield different results at chunksize {}.').format(i))

                prevJWS, crsNew, ids = state.getCashRegisterInfo(registerIdx)
                if crsOld != crsNew:
                    return TestVerifyResult.FAIL, Exception(
                            _('State update without verification failed.'))
                if recids != ids:
                    return TestVerifyResult.FAIL, Exception(
                            _('List of used receipt IDs invalid.'))
            else:
                # Save the _() function.
                trvec = (
                    __builtin__._ ,
                    depparser._,
                    key_store._,
                    receipt._,
                    verification_state._,
                    verify._,
                    verify_receipt._,
                )
                # Temporarily disable translations to make sure error
                # messages match.
                (
                    __builtin__._ ,
                    depparser._,
                    key_store._,
                    receipt._,
                    verification_state._,
                    verify._,
                    verify_receipt._,
                ) = [lambda x: x] * len(trvec)
                try:
                    state = verify.verifyDEP(dep, ks, key, state, registerIdx)
                finally:
                    (
                        __builtin__._ ,
                        depparser._,
                        key_store._,
                        receipt._,
                        verification_state._,
                        verify._,
                        verify_receipt._,
                    ) = trvec

            if expectedTurnover:
                prevJWS, cashRegState, ids = state.getCashRegisterInfo(registerIdx)
                expectedTurnoverCounter = int(round(expectedTurnover * 100))
                if expectedTurnoverCounter != cashRegState.lastTurnoverCounter:
                    return TestVerifyResult.FAIL, Exception(
                            _('Expected {} in turnover counter but got {}.').format(
                                expectedTurnoverCounter,
                                cashRegState.lastTurnoverCounter))
    except utils.RKSVVerifyException as e:
        actual_exception = e
    except Exception as e:
        return TestVerifyResult.ERROR, e

    actual_exception_is_instance = False
    if actual_exception:
        actual_exception_type = type(actual_exception).__name__
        expected_exception_class = _find_exception_class(expected_exception_type)
        if expected_exception_class:
            actual_exception_is_instance = isinstance(actual_exception,
                    expected_exception_class)

    if actual_exception_type != expected_exception_type and not actual_exception_is_instance:
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

def testVerify(spec, pub, priv, closed, proxy):
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
    :param proxy: An object implementing RKSVVerificationProxyI. This will
    be used to do the actual verification.
    :return: A TestVerifyResult indicating the result of the test and an
    error message. If the result is OK, the message is None.
    """
    try:
        keymat = [(pub, priv)] * spec['numberOfSignatureDevices']
        deps, cc = run_test.runTest(spec, keymat, closed)
    except Exception as e:
        return TestVerifyResult.ERROR, e

    rN, mN = _testVerify(spec, deps, cc, False, proxy)
    rP, mP = _testVerify(spec, deps, cc, True, proxy)
    if rN == rP and str(mN) == str(mP):
        return rN, mN

    r = TestVerifyResult.FAIL
    if rN == TestVerifyResult.ERROR or rP == TestVerifyResult.ERROR:
        r = TestVerifyResult.ERROR
    return r, Exception(
            _('Result mismatch: without parsing {}:>{}<, with parsing {}:>{}<').format(
                    rN.name, mN, rP.name, mP))

def testVerifyMulti(specs, groupLabel, crt, pub, priv, tcDefaultSize,
        proxy):
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
    :param proxy: An object implementing RKSVVerificationProxyI. This will
    be used to do the actual verification.
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
            result, msg = testVerify(s, pc, priv, closed, proxy)
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
