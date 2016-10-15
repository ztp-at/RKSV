#!/usr/bin/python3

from builtins import int

import json
import sys

import depexport
import receipt

def usage():
    print("Usage: ./convert.py json2csv")
    print("       ./convert.py csv2json")
    sys.exit(0)

if __name__ == "__main__":
    import gettext
    gettext.install('rktool', './lang', True)

    if len(sys.argv) != 2:
        usage()

    recs = list()
    if sys.argv[1] == 'json2csv':
        dep = json.loads(sys.stdin.read())
        exporter = depexport.CSVExporter()
        for g in dep['Belege-Gruppe']:
            exporter.addGroup([ receipt.Receipt.fromJWSString(r) for r
                    in g['Belege-kompakt'] ], g['Signaturzertifikat'],
                    g['Zertifizierungsstellen'])
    elif sys.argv[1] == 'csv2json':
        next(sys.stdin)
        for row in sys.stdin:
            recs.append(receipt.Receipt.fromCSV(row.strip()))
        exporter = depexport.JSONExporter()
        exporter.addGroup(recs)
    else:
        usage()

    print(exporter.export())
