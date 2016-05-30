#!/usr/bin/python3

from builtins import int

import json
import sys

from flask import Flask, abort, jsonify, make_response

import receipt

receipt_store = None

app = Flask(__name__)

NOT_FOUND = 404

@app.errorhandler(NOT_FOUND)
def not_found(error):
    return make_response(jsonify({ 'error': 'Not found'}), NOT_FOUND)

@app.route('/<string:url_hash>', methods = ['GET'])
def get_url_hash(url_hash):
    if url_hash not in receipt_store:
        abort(NOT_FOUND)

    return jsonify({'code': receipt_store[url_hash]})

def usage():
    print("Usage: ./receipt_host.py dep")
    print("       ./receipt_host.py jws")
    sys.exit(0)

if __name__ == "__main__":
    import gettext
    gettext.install('rktool', './lang', True)

    if len(sys.argv) != 2:
        usage()

    recs = dict()
    if sys.argv[1] == 'dep':
        dep = json.loads(sys.stdin.read())
        for g in dep['Belege-Gruppe']:
            for r in g['Belege-kompakt']:
                rec, pre = receipt.Receipt.fromJWSString(r)
                recs[rec.toURLHash(pre)] = rec.toBasicCode(pre)
    elif sys.argv[1] == 'jws':
        for l in sys.stdin:
            rec, pre = receipt.Receipt.fromJWSString(l.strip())
            recs[rec.toURLHash(pre)] = rec.toBasicCode(pre)
    else:
        usage()

    receipt_store = recs

    app.run(debug = True, use_reloader = False)
