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

import json
import os
import sys

import key_store
import utils
import verify

def usage():
    print("Usage: ./cert_extract.py <output dir>")
    sys.exit(0)

if __name__ == "__main__":
    import gettext
    gettext.install('rktool', './lang', True)

    if len(sys.argv) != 2:
        usage()

    outDir = sys.argv[1]
    if not os.path.exists(outDir):
        os.mkdir(outDir)
    os.chdir(outDir)

    dep = json.loads(sys.stdin.read())
    groups = verify.parseDEPAndGroups(dep)
    for recs, cert, cert_list in groups:
        groupCerts = list(cert_list)
        if cert:
            groupCerts.append(cert)

        for co in groupCerts:
            cs = key_store.numSerialToKeyId(co.serial)
            with open('{}.crt'.format(cs), 'w') as f:
                f.write(utils.addPEMCertHeaders(
                    utils.exportCertToPEM(co)))
