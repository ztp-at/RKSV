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

import base64
import configparser
import json
import sys

import gettext
gettext.install('rktool', './lang', True)

from librksv import utils
from librksv.key_store import KeyStore

def usage():
    print("Usage: ./key_store.py <key store> create")
    print("       ./key_store.py <key store> list")
    print("       ./key_store.py <key store> add <pem cert file>")
    print("       ./key_store.py <key store> add <pem pubkey file> <pubkey id>")
    print("       ./key_store.py <key store> del <pubkey id|cert serial>")
    print("       ./key_store.py <key store> showSymmetricKey")
    print("       ./key_store.py <key store> setSymmetricKey")
    print("       ./key_store.py <key store> delSymmetricKey")
    print("       ./key_store.py <key store> toLegacyIni")
    print("       ./key_store.py <key store> fromLegacyIni")
    sys.exit(0)

if __name__ == "__main__":
    # Do arg parsing first
    if len(sys.argv) < 3 or len(sys.argv) > 5:
        usage()
    if sys.argv[2] not in ['create', 'list', 'add', 'del',
            'showSymmetricKey', 'setSymmetricKey',
            'delSymmetricKey', 'toLegacyIni', 'fromLegacyIni']:
        usage()
    if len(sys.argv) == 5 and sys.argv[2] != 'add':
        usage()
    if len(sys.argv) == 4 and sys.argv[2] not in ['add', 'del']:
        usage()
    if len(sys.argv) == 3 and sys.argv[2] in ['add', 'del']:
        usage()

    if sys.argv[2] == 'create' or sys.argv[2] == 'fromLegacyIni':
        keyStore = KeyStore()
        symmetricKey = None
    else:
        with open(sys.argv[1], 'r') as f:
            data = utils.readJsonStream(f)
        keyStore = KeyStore.readStoreFromJson(data)
        symmetricKey = utils.loadKeyFromJson(data)

    if sys.argv[2] == 'list':
        for keyId in keyStore.getKeyIds():
            print(keyId)
        sys.exit(0)

    elif sys.argv[2] == 'add':
        newKey = None
        with open(sys.argv[3]) as f:
            newKey = f.read()

        if len(sys.argv) == 4:
            keyStore.putPEMCert(newKey)
        else:
            keyStore.putPEMKey(sys.argv[4], newKey)

    elif sys.argv[2] == 'del':
        keyStore.delKey(sys.argv[3])

    elif sys.argv[2] == 'showSymmetricKey':
        if symmetricKey is None:
            print(_('No symmetric key present.'))
        else:
            print(base64.b64encode(symmetricKey).decode('utf-8'))
        sys.exit(0)

    elif sys.argv[2] == 'setSymmetricKey':
        b64Key = None
        try:
            b64Key = next(sys.stdin).strip().encode('utf-8')
            if b64Key:
                symmetricKey = utils.loadB64Key(b64Key)
        except StopIteration:
            pass

        if not b64Key:
            sys.exit(0)

    elif sys.argv[2] == 'delSymmetricKey':
        symmetricKey = None

    elif sys.argv[2] == 'toLegacyIni':
        config = configparser.RawConfigParser()
        config.optionxform = str
        keyStore.writeStore(config)
        config.write(sys.stdout)
        sys.exit(0)

    elif sys.argv[2] == 'fromLegacyIni':
        config = configparser.RawConfigParser()
        config.optionxform = str
        config.read_file(sys.stdin)

        keyStore = KeyStore.readStore(config)
        symmetricKey = None

    if symmetricKey is None:
        b64Key = None
    else:
        b64Key = base64.b64encode(symmetricKey).decode('utf-8')

    data = keyStore.writeStoreToJson(b64Key)
    with open(sys.argv[1], 'w') as f:
        json.dump(data, f, sort_keys=False, indent=2)
