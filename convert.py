#!/usr/bin/env python2.7

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

import gettext
gettext.install('rktool', './lang', True)

import sys

from librksv import depexport
from librksv import depparser
from librksv import receipt
from librksv import utils

def usage():
    print("Usage: ./convert.py json2csv")
    print("       ./convert.py csv2json")
    sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        usage()

    recs = list()
    if sys.argv[1] == 'json2csv':
        parser = depparser.CertlessStreamDEPParser(sys.stdin)
        generator = depparser.receiptGroupAdapter(parser.parse(
            utils.depParserChunkSize()))
        stream = depexport.DEPStream(generator)
        exporter = depexport.CSVExporter(stream)
    elif sys.argv[1] == 'csv2json':
        next(sys.stdin)
        rec_generator = (receipt.Receipt.fromCSV(r.strip()) for r in sys.stdin)
        exporter = depexport.JSONExporter.fromSingleGroup(rec_generator)
    else:
        usage()

    for s in exporter.export():
        print(s, end='')
    print()
