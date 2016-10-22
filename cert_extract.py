#!/usr/bin/python3

from builtins import int

import json
import os
import sys

import key_store
import utils

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
    for g in dep['Belege-Gruppe']:
        groupCerts = []
        if 'Zertifizierungsstellen' in g:
            groupCerts = g['Zertifizierungsstellen']
        else:
            print(_('WARNING: {}').format(
                    _('\"{}\" missing from group element.').format(
                        'Zertifizierungsstellen')))

        if 'Signaturzertifikat' in g:
            groupCerts.append(g['Signaturzertifikat'])
        else:
            print(_('WARNING: {}').format(
                    _('\"{}\" missing from group element.').format(
                        'Signaturzertifikat')))

        for cert in groupCerts:
            try:
                co = utils.loadCert(utils.addPEMCertHeaders(cert))
                cs = key_store.numSerialToKeyId(co.serial)
                with open('{}.crt'.format(cs), 'w') as f:
                    f.write(utils.exportCertToPEM(co))
            except ValueError as e:
                print(_('WARNING: {}').format(
                    _('Cannot load certificate: {}').format(e)))
