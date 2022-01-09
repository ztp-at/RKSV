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

from builtins import int
from builtins import range

import sys

from six import string_types

import gettext
gettext.install('rktool', './lang', True)

from librksv import key_store
from librksv import receipt
from librksv import utils

from librksv.url_receipt_helpers import getAndVerifyReceiptURL
from librksv.verify_receipt import ReceiptVerifier

def receiptGenerator(lines):
    for l in lines:
        yield l.strip()

def singleInputToGenerator(inp):
    if isinstance(inp, string_types):
        return receiptGenerator([inp])
    return receiptGenerator(inp)

INPUT_FORMATS = {
        'jws': lambda rv, inp: (singleInputToGenerator(inp), rv.verifyJWS),
        'qr': lambda rv, inp: (singleInputToGenerator(inp), rv.verifyBasicCode),
        'ocr': lambda rv, inp: (singleInputToGenerator(inp), rv.verifyOCRCode),
        'url': lambda rv, inp: (singleInputToGenerator(inp),
            lambda s: getAndVerifyReceiptURL(rv, s)),
        'csv': lambda rv, inp: (singleInputToGenerator(inp), rv.verifyCSV)
        }

if __name__ == "__main__":
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Usage: ./verify_receipt.py <format> <key store> [<receipt string>]")
        sys.exit(0)

    if sys.argv[1] not in INPUT_FORMATS:
        print(_("Input format must be one of %s.") % INPUT_FORMATS.keys())
        sys.exit(0)

    rv = None
    with open(sys.argv[2], 'r') as f:
        data = utils.readJsonStream(f)
    keyStore = key_store.KeyStore.readStoreFromJson(data)
    rv = ReceiptVerifier.fromKeyStore(keyStore)

    if len(sys.argv) == 4:
        recs, ver = INPUT_FORMATS[sys.argv[1]](rv, sys.argv[3])
    else:
        recs, ver = INPUT_FORMATS[sys.argv[1]](rv, sys.stdin)

    idx = 0
    fails = 0
    for r in recs:
        try:
            ver(r)
        except receipt.ReceiptException as e:
            fails += 1
            print(str(_("Line {: >3}: {}")).format(idx, e))
        idx += 1

    print(_("{} of {} receipts verified successfully.").format(idx - fails, idx))
