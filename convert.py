#!/usr/bin/python3

import json
import sys

import depexport
import receipt

def usage():
    print("Usage: ./convert.py json2csv")
    print("       ./convert.py csv2json")
    sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        usage()

    recs = list()
    if sys.argv[1] == 'json2csv':
        dep = json.loads(sys.stdin.read())
        for g in dep['Belege-Gruppe']:
            recs = recs + [ receipt.Receipt.fromJWSString(r)[0] for r
                    in g['Belege-kompakt'] ]
        exporter = depexport.CSVExporter('R1')
    elif sys.argv[1] == 'csv2json':
        next(sys.stdin)
        for row in sys.stdin:
            recs.append(receipt.Receipt.fromCSV(row.strip())[0])
        exporter = depexport.DEPExporter('R1', None)
    else:
        usage()

    print(exporter.export(recs))
