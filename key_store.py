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
    print("       ./key_store.py <key store> toJson [<base64 AES key file>]")
    print("       ./key_store.py <key store> fromJson <json container file>")
    print("       ./key_store.py <key store> add <pem cert file>")
    print("       ./key_store.py <key store> add <pem pubkey file> <pubkey id>")
    print("       ./key_store.py <key store> del <pubkey id|cert serial>")
    sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()

    filename = sys.argv[1]
    keyStore = None

    if sys.argv[2] == 'create':
        if len(sys.argv) != 3:
            usage()

        keyStore = KeyStore()

    elif sys.argv[2] == 'list':
        if len(sys.argv) != 3:
            usage()

        config = configparser.RawConfigParser()
        config.optionxform = str
        config.read(filename)
        keyStore = KeyStore.readStore(config)

        for keyId in keyStore.getKeyIds():
            print(keyId)

    elif sys.argv[2] == 'toJson':
        if len(sys.argv) > 4:
            usage()

        config = configparser.RawConfigParser()
        config.optionxform = str
        config.read(filename)
        keyStore = KeyStore.readStore(config)

        aesKey = None
        if len(sys.argv) == 4:
            with open(sys.argv[3]) as f:
                aesKey = f.read().strip()

        data = keyStore.writeStoreToJson(aesKey)
        print(json.dumps(data, sort_keys=False, indent=2))

    elif sys.argv[2] == 'fromJson':
        if len(sys.argv) != 4:
            usage()

        keyStore = None
        with open(sys.argv[3]) as f:
            keyStore = KeyStore.readStoreFromJson(utils.readJsonStream(f))

    elif sys.argv[2] == 'add':
        if len(sys.argv) < 4:
            usage()

        config = configparser.RawConfigParser()
        config.optionxform = str
        config.read(filename)
        keyStore = KeyStore.readStore(config)

        newKey = None
        with open(sys.argv[3]) as f:
            newKey = f.read()

        if len(sys.argv) == 4:
            keyStore.putPEMCert(newKey)
        elif len(sys.argv) == 5:
            keyStore.putPEMKey(sys.argv[4], newKey)
        else:
            usage()

    elif sys.argv[2] == 'del':
        if len(sys.argv) != 4:
            usage()

        config = configparser.RawConfigParser()
        config.optionxform = str
        config.read(filename)
        keyStore = KeyStore.readStore(config)

        keyStore.delKey(sys.argv[3])

    else:
        usage()

    config = configparser.RawConfigParser()
    config.optionxform = str
    keyStore.writeStore(config)
    with open(filename, 'w') as f:
        config.write(f)
