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

from builtins import int

import sys

import gettext
gettext.install('rktool', './lang', True)

from librksv.receipt import Receipt
from librksv import utils

INPUT_FORMATS = {
        'jws': lambda s: Receipt.fromJWSString(s),
        'qr': lambda s: Receipt.fromBasicCode(s),
        'ocr': lambda s: Receipt.fromOCRCode(s),
        'url': lambda s: Receipt.fromBasicCode(utils.getBasicCodeFromURL(
            s)),
        'csv': lambda s: Receipt.fromCSV(s)
        }

OUTPUT_FORMATS = {
        'jws': lambda r, p: r.toJWSString(p),
        'qr': lambda r, p: r.toBasicCode(p),
        'ocr': lambda r, p: r.toOCRCode(p),
        'url': lambda r, p: r.toURLHash(p),
        'csv': lambda r, p: r.toCSV(p)
        }

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: ./receipt.py <in format> <out format>")
        sys.exit(0)

    if sys.argv[1] not in INPUT_FORMATS:
        print(_("Input format must be one of %s.") % INPUT_FORMATS.keys())
        sys.exit(0)

    if sys.argv[2] not in OUTPUT_FORMATS:
        print(_("Output format must be one of %s.") % OUTPUT_FORMATS.keys())
        sys.exit(0)

    for l in sys.stdin:
        r, p = INPUT_FORMATS[sys.argv[1]](l.strip())
        s = OUTPUT_FORMATS[sys.argv[2]](r, p)
        print(s)
