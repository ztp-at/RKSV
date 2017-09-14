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

import os
import sys

import gettext
gettext.install('rktool', './lang', True)

from librksv import depexport
from librksv import depparser
from librksv import receipt

def usage():
    print("Usage: ./split.py <chunk size> <output dir>")
    sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        usage()

    chunksize = int(sys.argv[1])
    if chunksize < 1:
        usage()

    outDir = sys.argv[2]
    if not os.path.exists(outDir):
        os.mkdir(outDir)
    os.chdir(outDir)

    parser = depparser.IncrementalDEPParser.fromFd(sys.stdin, True)
    i = 0
    for chunk in parser.parse(chunksize):
        exporter = depexport.JSONExporter()
        for recs, cert, cert_list in chunk:
            exporter.addGroup([ receipt.Receipt.fromJWSString(
                depparser.expandDEPReceipt(r)) for r in recs ], cert, cert_list)

        dep = exporter.export()
        with open('dep-export{}.json'.format(i), 'w') as f:
            f.write(dep)

        i += 1
