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

from builtins import int
from builtins import range

import gettext
gettext.install('rktool', './lang', True)

import os
import sys

from librksv import depparser
from librksv import key_store
from librksv import utils

def usage():
    print("Usage: ./cert_extract.py <output dir>")
    sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        usage()

    outDir = sys.argv[1]
    if not os.path.exists(outDir):
        os.mkdir(outDir)
    os.chdir(outDir)

    parser = depparser.CertlessStreamDEPParser(sys.stdin)
    for chunk in parser.parse(utils.depParserChunkSize()):
        for recs, cert, cert_list in chunk:
            groupCerts = list(cert_list)
            if cert:
                groupCerts.append(cert)

            for co in groupCerts:
                cs = key_store.numSerialToKeyId(co.serial)
                with open('{}.crt'.format(cs), 'w') as f:
                    f.write(utils.addPEMCertHeaders(
                        utils.exportCertToPEM(co)))

            recs = None
        chunk = None
