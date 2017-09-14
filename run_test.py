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

import gettext
gettext.install('rktool', './lang', True)

from librksv.run_test import runTest

def usage():
    print("Usage: ./run_test.py open <JSON test case spec> <cert 1 priv> <cert 1> [<cert 2 priv> <cert 2>]... [<turnover counter size>]")
    print("       ./run_test.py closed <JSON test case spec> <key 1 priv> <pub key 1> [<key 2 priv> <pub key 2>]... [<turnover counter size>]")
    sys.exit(0)

if __name__ == "__main__":
    import gettext
    gettext.install('rktool', './lang', True)

    if len(sys.argv) < 5:
        usage()

    closed = False
    if sys.argv[1] == 'closed':
        closed = True
    elif sys.argv[1] != 'open':
        usage()

    tcJson = None
    with open(sys.argv[2]) as f:
        tcJson = json.loads(f.read())

    if len(sys.argv) != (tcJson['numberOfSignatureDevices'] * 2 + 3
            ) and len(sys.argv) != (tcJson['numberOfSignatureDevices']
                    * 2 + 3 + 1):
        print(_("I need keys and certificates for %d signature devices.") %
                tcJson['numberOfSignatureDevices'])
        sys.exit(0)

    baseDir = tcJson['simulationRunLabel']
    if not os.path.exists(baseDir):
        os.mkdir(baseDir)

    turnoverCounterSize = None
    if len(sys.argv) % 2 != 1:
        turnoverCounterSize = int(sys.argv[-1])
        if turnoverCounterSize < 5 or turnoverCounterSize > 16:
            print(_("Turnover counter size needs to be between 5 and 16."))
            sys.exit(0)

    keymat = list()
    for i in range(tcJson['numberOfSignatureDevices']):
        pub = None
        priv = None
        with open(sys.argv[i * 2 + 1 + 3]) as f:
            pub = f.read()
        with open(sys.argv[i * 2 + 3]) as f:
            priv = f.read()
        keymat.append((pub, priv))

    deps, ks = runTest(tcJson, keymat, closed, turnoverCounterSize)

    os.chdir(baseDir)

    with open('cryptographicMaterialContainer.json', 'w') as f:
        f.write(json.dumps(ks, sort_keys=False, indent=2))

    if len(deps) == 1:
        with open('dep-export.json', 'w') as f:
            f.write(json.dumps(deps[0], sort_keys=False, indent=2))
    else:
        for i in range(len(deps)):
            with open('dep-export{}.json'.format(i), 'w') as f:
                f.write(json.dumps(deps[i], sort_keys=False, indent=2))
