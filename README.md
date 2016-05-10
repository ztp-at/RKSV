Dependencies
------------
>=python-3.4
>=Kivy-1.9 (for the UI)
>=cryptography-1.2
>=dev-python/flask-0.10.1-r1
>=dev-python/pyjwt-1.3
>=dev-python/six-1.10.0

setup.sh:
---------

Generates an AES key (`aesBase64.txt`), a private key (`cert.key`),
a public key (`cert.pub`) and a certificate signed with the private key
(`cert.crt`). The keys and certificates are stored in PEM format while the
AES key is stored as base64 encoded text.

demo.py
-------
	Usage: ./demo.py <private key file> <cert file> <base64 AES key file> <number of receipts>
	       ./demo.py <private key file> <public key file> <key ID> <base64 AES key file> <number of receipts>
	       ./demo.py <base64 AES key file> <number of receipts>

The first invocation generates a DEP with `number of receipts` receipts
and signs them with the given private key. The certificate is used to
obtain the serial number to use in the receipts.

The second invocation generates a DEP file, but uses the given key ID in
the receipts and does not include a certificate in the DEP export. The
public key file should contain the public key to the given private key.

The third invocation generates a DEP file but uses the Registrierkasse Mobile
service from A-Trust to create the signatures. It uses the default test login
(`u123456789`:`123456789`) and the SSL certificates in `A-Trust-Stamm.pem`. The
certificate used to sign the receipts is located in `regk-mobile-test.crt` or
can be downloaded from the A-Trust service.

The AES key file should contain the key used to encrypt the turnover
counter in each receipt as base64 encoded text.

Certificate and key files are expected to be in PEM format.

run_test.py
-----------
	Usage: ./run_test.py open <JSON test case spec> <cert 1 priv> <cert 1> [<cert 2 priv> <cert 2>]...
	       ./run_test.py closed <JSON test case spec> <key 1 priv> <pub key 1> [<key 2 priv> <pub key 2>]...

This script takes the mode and a test run specification in JSON format as the
first two parameters and private key files and public key/certificate files for
each used signature system as subsequent parameters.

It simulates a cash register running the specified test case. The output is
stored in a directory named after the test case (the `simulationRunLabel`
property). The DEP is stored in the file `dep-export.json` and the cryptographic
material (AES keys, certificates, public keys etc.) is stored in
`cryptographicMaterialContainer.json` in the JSON container format.

The `open` mode simulates an open system and uses certificates. The `closed`
mode simulates a closed system and uses plain public keys.

key_store.py
------------
	Usage: ./key_store.py <key store> create
	       ./key_store.py <key store> list
	       ./key_store.py <key store> fromJson <json container file>
	       ./key_store.py <key store> add <pem cert file>
	       ./key_store.py <key store> add <pem pubkey file> <pubkey id>
	       ./key_store.py <key store> del <pubkey id|cert serial>

The `create` command creates a new empty key store in the file `key store`.

The `list` command lists the known certificate serials and key IDs

The `fromJson` command creates a new key store from the new JSON crypto
container format defined in version 0.6 of the reference implementation.

The first `add` command adds a PEM certificate to the key store using the
certificate's serial number as ID.

The second `add` command adds a PEM public key to the key store using
`pubkey id` as ID.

The `del` command deletes the key or certificate with the given ID.

A key store is just a simple `.ini` file.

receipt.py
-----------

	Usage: ./receipt.py <in format> <out format>

This script reads receipts from stdin and writes them to stdout, possibly
converting them to a different format. The supported input formats are
`jws`, `qr`, `ocr`, `url` and `csv`. The supported output formats are `jws`,
`qr`, `ocr`, `url` and `csv`.

verify.py
---------
	Usage: ./verify.py keyStore <key store> <dep export file> [<base64 AES key file>]
	       ./verify.py json <json container file> <dep export file>

This script, when called with the `keyStore` command, verifies the given DEP
export file. The used certificates or public keys must be available in the given
key store. If the DEP is valid the script prints nothing, if it is not then the
script will print an error message.

If an AES key file is specified, the script will also check the turnover
counter in each receipt.

When the script is called with the `json` command it will instead read the
certificates and the AES key from a cryptographic material container JSON file.

verify_receipt.py
-----------------
	Usage: ./verify_receipt.py <format> <key store> [<receipt string>]

This script verifies receipts. The used certificates or public keys must be
available in the given key store. The formats `jws`, `qr`, `ocr` and `csv` are
supported. If `receipt string` is given, the receipt from the command line is
verified, otherwise the script reads and verifies receipts from stdin. If all
receipts are valid the script prints nothing, if the verification fails it will
print an error message.

convert.py
----------
	Usage: ./convert.py json2csv
	       ./convert.py csv2json

The convert script allows to convert a JSON DEP to CSV and vice-versa. The
input file is read from stdin and the output is written to stdout.

If a JSON file contains multiple groups of receipts, they are merged. Groups and
certificates are not mapped into the CSV and hence cannot be restored when
converting back to JSON.

The CSV contains one receipt per line with `;` serving as the delimiter.

receipt_host.py
---------------
	Usage: ./receipt_host.py dep
       	       ./receipt_host.py jws

This script reads receipts from stdin and launches a web server on
`127.0.0.1:5000` that hosts each receipt under `/<url_hash>`, where `<url_hash>`
is the URL format of the receipt as returned by the `receipt.py` script.

The first invocation expects the receipts in a DEP formatted file, while the
second one expects one JWS formatted receipt per line.

rktool.py
---------
This script provides a GUI to access some of the functionality provided by the
previously mentioned tools. It provides interfaces to manage key stores, verify
DEP files and import and verify single receipts from various sources.
