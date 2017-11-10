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

import codecs
import json
import multiprocessing
import os
import random
import sys

import gettext
gettext.install('rktool', './lang', True)

from librksv.test import test_verify
from librksv.test import verification_proxy

def usage():
    print("Usage: ./test_verify.py open <JSON test case spec> <cert priv> <cert> [<turnover counter size>]")
    print("       ./test_verify.py closed <JSON test case spec> <key priv> <pub key> [<turnover counter size>]")
    print("       ./test_verify.py multi <key priv> <cert> <pub key> <turnover counter size 1>,... <group label> <JSON test case spec 1>...")
    sys.exit(3)

if __name__ == "__main__":
    def get_seed():
        return os.environ.get('RKSV_TEST_SEED',
                codecs.encode(os.urandom(8), 'hex').decode('utf-8'))

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

    # We should always test with multiprocessing to catch pickle issues.
    DEFAULT_NPROCS = 2

    seed = get_seed()
    random.seed(seed)
    print(_('Using seed \"{}\"').format(seed))

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
        proxy = verification_proxy.LibRKSVVerificationProxy(pool, DEFAULT_NPROCS)
        results = test_verify.testVerifyMulti(specs, groupLabel, cert, pub, priv, 8,
                proxy)

        resultList = list()
        try:
            for r in results:
                test_verify.printTestVerifyResult(*r)
                resultList.append(r)
        finally:
            pool.terminate()
            pool.join()

        test_verify.printTestVerifySummary(resultList)
        print(_('Used seed \"{}\"').format(seed))

        if any(r[4] == test_verify.TestVerifyResult.ERROR for r in resultList):
            sys.exit(2)
        if any(r[4] == test_verify.TestVerifyResult.FAIL for r in resultList):
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
    proxy = verification_proxy.LibRKSVVerificationProxy(pool, DEFAULT_NPROCS)
    try:
        result, msg = test_verify.testVerify(tcJson, pub, priv, closed, proxy)
    finally:
        pool.terminate()
        pool.join()

    test_verify.printTestVerifyResult(test_name, 'no Group', closed, tc_size, result,
            msg)
    print(_('Used seed \"{}\"').format(seed))

    if result == test_verify.TestVerifyResult.ERROR:
        sys.exit(2)
    if result == test_verify.TestVerifyResult.FAIL:
        sys.exit(1)
    sys.exit(0)
