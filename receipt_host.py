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

import sys

from flask import Flask, abort, jsonify, make_response

import gettext
gettext.install('rktool', './lang', True)

from librksv import depparser
from librksv import receipt
from librksv import utils

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
    if len(sys.argv) != 2:
        usage()

    receipts = dict()
    if sys.argv[1] == 'dep':
        parser = depparser.CertlessStreamDEPParser(sys.stdin)
        for chunk in parser.parse(utils.depParserChunkSize()):
            for recs, cert, cert_list in chunk:
                for cr in recs:
                    r = depparser.expandDEPReceipt(cr)
                    rec, pre = receipt.Receipt.fromJWSString(r)
                    receipts[rec.toURLHash(pre)] = rec.toBasicCode(pre)
    elif sys.argv[1] == 'jws':
        for l in sys.stdin:
            rec, pre = receipt.Receipt.fromJWSString(l.strip())
            receipts[rec.toURLHash(pre)] = rec.toBasicCode(pre)
    else:
        usage()

    receipt_store = receipts

    app.run(debug = True, use_reloader = False)
