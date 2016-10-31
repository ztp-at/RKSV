#!/usr/bin/env python2.7

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
                f.write(utils.exportCertToPEM(co))
