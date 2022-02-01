#!/usr/bin/env python3

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

import json
import os
import sys

import gettext
gettext.install('rktool', './lang', True)

from librksv import depparser
from librksv import key_store
from librksv import utils
from librksv import verification_state
from librksv import verify_receipt

from librksv.verify import verifyDEP, verifyParsedDEP

def getReceiptVerifier():
    rv = verify_receipt.ReceiptVerifier

    if int(os.environ.get('RKSV_RECEIPT_ERRORS_TO_STDERR', 0)) == 1:
        rv = verify_receipt.StderrReceiptVerifier

    return rv

def usage():
    print("Usage: ./verify.py [state [continue|<n>]] [par <n>] [chunksize <n>] [json] <key store> <dep export file>",
            file=sys.stderr)
    print("       ./verify.py state", file=sys.stderr)
    sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 10:
        usage()

    key = None
    keyStore = None

    statePassthrough = False
    continueLast = False
    registerIdx = None
    if sys.argv[1] == 'state':
        statePassthrough = True
        del sys.argv[1]

    if statePassthrough and len(sys.argv) == 1:
        print(json.dumps(
            verification_state.ClusterState().writeStateToJson(),
            sort_keys=False, indent=2))
        sys.exit(0)

    if sys.argv[1] == 'continue':
        continueLast = True
        del sys.argv[1]
    else:
        try:
            registerIdx = int(sys.argv[1])
            del sys.argv[1]
        except ValueError:
            pass

    if len(sys.argv) < 3 or len(sys.argv) > 8:
        usage()

    nprocs = 1
    if sys.argv[1] == 'par':
        del sys.argv[1]
        try:
            nprocs = int(sys.argv[1])
            del sys.argv[1]
        except ValueError:
            usage()
    if nprocs < 1:
        usage()

    if len(sys.argv) < 3 or len(sys.argv) > 6:
        usage()

    chunksize = utils.depParserChunkSize()
    if sys.argv[1] == 'chunksize':
        del sys.argv[1]
        try:
            chunksize = int(sys.argv[1])
            del sys.argv[1]
        except ValueError:
            usage()
    if chunksize < 0:
        usage()

    if len(sys.argv) < 3 or len(sys.argv) > 4:
        usage()

    # We allow this for backwards compatibility.
    if sys.argv[1] == 'json':
        del sys.argv[1]

    if len(sys.argv) != 3:
        usage()

    with open(sys.argv[1]) as f:
        jsonStore = utils.readJsonStream(f)

        key = utils.loadKeyFromJson(jsonStore)
        keyStore = key_store.KeyStore.readStoreFromJson(jsonStore)

    state = None
    if statePassthrough:
        state = verification_state.ClusterState.readStateFromJson(
                utils.readJsonStream(sys.stdin))
        if continueLast:
            registerIdx = len(state.cashRegisters) - 1

    if nprocs > 1:
        import multiprocessing
        pool = multiprocessing.Pool(nprocs)

        try:
            with open(sys.argv[2]) as f:
                if chunksize == 0:
                    parser = depparser.FullFileDEPParser(f, nprocs)
                else:
                    parser = depparser.IncrementalDEPParser.fromFd(f, True)

                state = verifyParsedDEP(parser, keyStore, key, state, registerIdx,
                        pool, nprocs, chunksize,
                        verification_state.DEFAULT_USED_RECEIPT_IDS_BACKEND,
                        getReceiptVerifier())
        finally:
            pool.terminate()
            pool.join()
    else:
        with open(sys.argv[2]) as f:
            if chunksize == 0:
                dep = utils.readJsonStream(f)
                state = verifyDEP(dep, keyStore, key, state, registerIdx,
                        verification_state.DEFAULT_USED_RECEIPT_IDS_BACKEND,
                        getReceiptVerifier())
            else:
                parser = depparser.IncrementalDEPParser.fromFd(f, True)
                state = verifyParsedDEP(parser, keyStore, key, state, registerIdx,
                        None, nprocs, chunksize,
                        verification_state.DEFAULT_USED_RECEIPT_IDS_BACKEND,
                        getReceiptVerifier())

    if statePassthrough:
        print(json.dumps(
            state.writeStateToJson(), sort_keys=False, indent=2))

    print(_("Verification successful."), file=sys.stderr)
