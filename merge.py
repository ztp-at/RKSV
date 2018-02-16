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

import sys

import gettext
gettext.install('rktool', './lang', True)

from librksv import depexport
from librksv import depparser
from librksv import receipt
from librksv import utils

def usage():
    print("Usage: ./merge.py [groups] <input file 1> <input file 2>...")
    sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()

    # check if adjacent groups should be merged if they are the same
    streamcls = depexport.DEPStream
    if sys.argv[1] == 'groups':
        streamcls = depexport.MergingDEPStream
        del sys.argv[1]

    if len(sys.argv) < 3:
        usage()

    # get the chunksize for the individual parsers
    csz = utils.depParserChunkSize()
    fds = list()
    try:
        # open all input files
        for infile_name in sys.argv[1:]:
                fds.append(open(infile_name, 'r'))

        # build the parser-stream-exporter pipeline
        ps = [ depparser.IncrementalDEPParser.fromFd(f, True) for f in fds ]
        gs = [ depparser.receiptGroupAdapter(p.parse(csz)) for p in ps ]
        stream = depexport.MergingDEPStream.fromIterList(gs)
        exporter = streamcls(stream)

        # export as one DEP
        for s in exporter.export():
            print(s, end='')
        print()
    finally:
        for f in fds:
            f.close()
