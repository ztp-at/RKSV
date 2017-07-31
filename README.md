Python RKSV Scripts
===================
**(c) ZTP.at**

This repository contains a collection of scripts for verifying and
analyzing cash register logs (DEPs) and signed receipts according to the
Registrierkassensicherheitsverordnung (RKSV).

A German tutorial for some of the tools here is available in the
[Wiki](https://github.com/ztp-at/RKSV/wiki).

Disclaimer
----------

The verification tools available here are not fit to ensure the correct
functioning of a cash register implementation according to law. The
correctness of the verification results cannot be guaranteed. In case
of uncertanties the official service provided by the Austrian Federal 
Ministry of Finance should be consulted.

Furthermore, no part of the code in this repository is fit to be used in a
cash register in productive use.

License
-------

All scripts and source files are licensed under the AGPLv3.

Dependencies
------------
To run `make env`:
* gnu-make >=4.1
* libffi >=3.2.1 + development headers
* libgl1-mesa >=11.2.0 + development headers
* mesa-common >=11.2.0 + development headers
* openssl >=1.0.2g + development headers
* python >=2.7.10
* libpython >=2.7.10 + development headers
* python-virtualenv >=13.1.2
* zbar >=0.10 + development headers
* a working compiler toolchain

To use on Linux:
* Kivy >=1.9.1
* dev-python/configparser >=3.3.0.2
* dev-python/cryptography >=1.2
* dev-python/cython >=0.24.1
* dev-python/enum34 >=1.0.4
* dev-python/flask >=0.10.1
* dev-python/future >=0.15.2
* dev-python/pillow >=3.1.1
* dev-python/pygame >=1.9.2
* dev-python/pyjwt >=1.3
* dev-python/requests >=2.8.1
* dev-python/six >=1.10.0
* zbar Python bindings

Additionally needed to compile the translations:
* pygettext.py in PATH
* gnu-gettext >=0.19.7

Additionally needed to build the APK:
* autoconf >=2.69
* dev-python/appdirs >=1.4.0
* dev-python/colorama >=0.33
* dev-python/jinja >=2.8
* dev-python/sh >=1.11
* git >=2.7.3
* libncurses5:i386 >=6.0 (for x86_64 systems)
* libstdc++6:i386 >=5.4.0 (for x86_64 systems)
* openjdk >=8
* unzip >=6.0
* wget >=1.17.1
* zlib1g:i386 >=1.2.8 (for x86_64 systems)

On Ubuntu 16.04 you can install all requirements to create the Python virtual
environment to run all scripts with `apt-get install python-virtualenv
mesa-common-dev libgl1-mesa-dev libssl-dev libpython2.7-dev libzbar-dev
build-essential gettext libffi-dev`. The requirements needed to build the APK
can be installed with `dpkg --add-architecture i386 && apt-get update &&
apt-get install default-jdk git unzip wget libncurses5:i386 libstdc++6:i386
zlib1g:i386 autoconf`.


Dockerfile
----------

Using the included `Dockerfile`, you can create a Docker container
containing all the necessary dependencies to run any of the scripts and to
build the APK.

The container also includes an SSH server that can be started with `service
ssh start`. The default user (and password) is `rksv`. Together with X11
forwarding, the SSH server can be used to run the GUI.

Managing large DEPs
-------------------

As larger DEPs may take up too much space to be resident entirely in memory, all
scripts that read DEP JSON files (except for the `rktool.py` GUI) use an
incremental parser to read and process a file in several chunks. The default
number of receipts per chunks is `100000` and can be adjusted with the
`RKSV_DEP_CHUNKSIZE` environment variable. A higher chunk size can increase
performance but requires more memory, while a lower chunk size can reduce memory
usage at the cost of speed. A chunk size of zero will cause the entire DEP to be
read into memory.

As the incremental parser needs to return the appropriate certificates for each
chunk it generates, it may need to locate the certificate and certificate chain
elements in each DEP group before all receipts have been read. Therefore,
receipts either need to be placed _after_ these elements or the parser needs to
parse the DEP twice (first to locate the certificate elements, second to read
the receipts in chunks), thus requiring more time and a seekable file (i.e. not
a Pipe or a Socket). For optimal performance the certificate and certificate
chain elements should be placed _before_ the receipt list in each group in the
DEP file.

make env
--------

Creates a Python virtual environment with everything needed to run the scripts
on a Linux system. The environment can be activated by running `source
.pyenv/bin/activate`. If you did not install all the dependencies listed above
but only those required to run `make env`, you will need to use the environment
created by `make env` to execute any of the commands below.

make setup
----------

Generates an AES key (`aesBase64_1.txt`), a private key (`cert_1.key`),
a public key (`cert_1.pub`) and a certificate signed with the private key
(`cert_1.crt`). The keys and certificates are stored in PEM format while the
AES key is stored as base64 encoded text.

make test
---------

Runs `test_verify.py` for all test cases in `tests` for open and closed systems
with turnover counters of 5, 8 and 16 bytes with both Python 2 and 3. If no
certificate has been generated yet, it will create one first.

make update-trans
-----------------

Updates the `*.po` files in `lang` by merging them with a newly created `*.pot`
file based on the extracted translatable strings.

make compile-trans
------------------

Compiles the `*.po` files in `lang` to `*.mo` files so that they can be used to
read the translations for various strings in the Python scripts.

make apk
--------

Packages the `rktool.py` application into an `*.apk` file which can be installed
on an Android device.

make clean
----------

Removes all intermediate files created by the Python interpreters or by the
translation facilities. Also removes all certificates and keys created by `make
setup`.

make dist-clean
---------------

Like `make clean` but also removes all intermediate files created by `make apk`
and `make env`. Make sure to leave the Python virtual environment created by
`make env` by calling `deactivate` before doing a `make dist-clean`.

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
(`u123456789`:`123456789`) and the SSL certificates in `misc/A-Trust-Stamm.pem`.
The certificate used to sign the receipts is located in
`misc/regk-mobile-test.crt` or can be downloaded from the A-Trust service.

The AES key file should contain the key used to encrypt the turnover
counter in each receipt as base64 encoded text.

Certificate and key files are expected to be in PEM format.

run_test.py
-----------
	Usage: ./run_test.py open <JSON test case spec> <cert 1 priv> <cert 1> [<cert 2 priv> <cert 2>]... [<turnover counter size>]
	       ./run_test.py closed <JSON test case spec> <key 1 priv> <pub key 1> [<key 2 priv> <pub key 2>]... [<turnover counter size>]

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

The optional last parameter indicates the size of the turnover counter in bytes.

key_store.py
------------
	Usage: ./key_store.py <key store> create
	       ./key_store.py <key store> list
	       ./key_store.py <key store> toJson <base64 AES key file>
	       ./key_store.py <key store> fromJson <json container file>
	       ./key_store.py <key store> add <pem cert file>
	       ./key_store.py <key store> add <pem pubkey file> <pubkey id>
	       ./key_store.py <key store> del <pubkey id|cert serial>

The `create` command creates a new empty key store in the file `key store`.

The `list` command lists the known certificate serials and key IDs

The `toJson` command prints the key store in the new JSON crypto container
format defined in version 0.6 of the reference implementation. It requires a
file containing the base64 encoded AES256 key as a parameter.

The `fromJson` command creates a new key store from the new JSON crypto
container format defined in version 0.6 of the reference implementation.

The first `add` command adds a PEM certificate to the key store using the
certificate's serial number as ID.

The second `add` command adds a PEM public key to the key store using
`pubkey id` as ID.

The `del` command deletes the key or certificate with the given ID.

A key store is just a simple `.ini` file.

verification_state.py
---------------------
	Usage: ./verification_state.py <state> create
	       ./verification_state.py <state> show
	       ./verification_state.py <state> addCashRegister
	       ./verification_state.py <state> resetCashRegister <n>
	       ./verification_state.py <state> deleteCashRegister <n>
	       ./verification_state.py <state> copyCashRegister <n-Target> <source state file> <n-Source>
	       ./verification_state.py <state> updateCashRegister <n-Target> <dep export file> [<base64 AES key file>]
	       ./verification_state.py <state> setLastReceiptJWS <n> <receipt in JWS format>
	       ./verification_state.py <state> setLastTurnoverCounter <n> <counter in cents>
	       ./verification_state.py <state> toggleNeedRestoreReceipt <n>
	       ./verification_state.py <state> setStartReceiptJWS <n> <receipt in JWS format>
	       ./verification_state.py <state> readUsedReceiptIds <file with one receipt ID per line>

This script manages the verification state if multiple related DEPs need to be
verified. A state store is a simple JSON file. It contains a list of used receipt
IDs and a list of cash register states. The cash register states record the
start receipt of a cash register, the last verified receipt, the last known
turnover counter (if available) and whether or not the next receipt has to be a
signed null receipt. For open systems and regular closed systems, the state
should contain only one cash register. If GGS clusters are used, the state
contains an entry for every register in the cluster.

A verification state allows to split DEPs into multiple segments and verify them
one by one or to allow the verification of DEPs generated by GGS clusters.

The `create` command creates a new empty verification state in the file `state`.

The `show` command displays the information stored in the state file.

The `addCashRegister` command adds a new cash register to the state (for a GGS
cluster).

The `resetCashRegister` command resets the information in the nth cash register
state to its initial values. Note that this operation can result in an
inconsistent state as the start receipt is lost and the start receipt of the
(n+1)st register can not be verified.

The `deleteCashRegister` command removes the nth cash register from the state.
Note that this operation can result in an inconsistent state as the start
receipt is lost and the start receipt of the (n+1)st register can not be
verified.

The `copyCashRegister` command copies the state of the n-Source-th cash register
from the specified source state file to the n-Target-th cash register state.
Note that this operation can result in an inconsistent state as the start
receipt is lost and the start receipt of the (n-Target+1)st register can not be
verified.

The `updateCashRegister` command updates the state of the n-Target-th cash
register as if the DEP in `dep export file` had been verified. If an AES
key is specified in `base64 AES key file`, the turnover counter is updated
as well.

The `setLastReceiptJWS` command sets the last known receipt for the nth cash
register to the given value.

The `setLastTurnoverCounter` command sets the last known turnover counter for
the nth cash register to the given value.

The `toggleNeedRestoreReceipt` command toggles the value indicating whether the
next receipt for the nth cash register must be a signed null receipt.

The `setStartReceiptJWS` command sets the start receipt for the nth cash
register to the given value. Note that this operation can result in an
inconsistent state as the start receipt is lost and the start receipt of the
(n+1)st register can not be verified.

The `readUsedReceiptIds` command reads the list of used receipt IDs from the
specified file.

receipt.py
-----------

	Usage: ./receipt.py <in format> <out format>

This script reads receipts from stdin and writes them to stdout, possibly
converting them to a different format. The supported input formats are
`jws`, `qr`, `ocr`, `url` and `csv`. The supported output formats are `jws`,
`qr`, `ocr`, `url` and `csv`.

verify.py
---------
	Usage: ./verify.py [state [continue|<n>]] [par <n>] [chunksize <n>] keyStore <key store> <dep export file> [<base64 AES key file>]
	       ./verify.py [state [continue|<n>]] [par <n>] [chunksize <n>] json <json container file> <dep export file>
	       ./verify.py state

This script, when called with the `keyStore` command, verifies the given DEP
export file. The used certificates or public keys must be available in the given
key store. If the DEP is valid the script prints a short success message, if it
is not then the script will print an error message.

If an AES key file is specified, the script will also check the turnover
counter in each receipt.

When the script is called with the `json` command it will instead read the
certificates and the AES key from a cryptographic material container JSON file.

When just `state` is specified, the script will emit the JSON for an empty
verification state to stdout.

If `state` is specified before the `keyStore` or `json` commands, the script
expects a JSON state store on stdin and emits the modified store after
verification to stdout. The state store can contain multiple cash registers but
may only do so if the DEP belongs to a register in a GGS cluster.

`state <n>` instructs the script to interpret the DEP as a continuation of the
nth cash register in the read state. Verification will expect the first receipt
in the DEP to chain to the last receipt recorded in the state for that register
or to the start receipt of the (n-1)st register if no receipts have been
recorded for the nth register.

`state continue` instructs the script to interpret the DEP as a continuation of
the last cash register in the read state.

Finally, `state` on its own will append a new cash register and treat the DEP as
the first DEP for this new cash register.

The `par` keyword will instruct the script to use the following positive
number as the number of parallel processes to use for verifying the DEP. If
it is omitted, a single process will be used.

The `chunksize` keyword will set the number of receipts that are processed as
one chunk. If the keyword is missing, the default chunk size or (if available)
the chunk size in the `RKSV_DEP_CHUNKSIZE` environment variable will be used. If
the `par` keyword was also used, the script will read a chunk for every process,
dispatch the chunks for verification to the processes, and repeat this until no
chunks are left. If a chunk size of zero is specified, the script will read the
entire DEP at once and evenly distribute the receipts among the processes. Note
that all receipts in a chunk must fit in memory at the same time. If multiple
processes are used one chunk for every process must fit into memory at the same
time.

Note that even when a non-zero chunk size is used, the required memory
increases linearly with the total number of receipts in the DEP. This is
because the script needs to keep track of the used receipt IDs to detect
duplicates. A possible workaround is to split the DEP into multiple files and
use the `state` keyword to verify them while clearing the list of receipts in
each state JSON. In this case however, `verify.py` will only be able to
ascertain the uniqueness of receipt IDs within one file.

test_verify.py
--------------
	Usage: ./test_verify.py open <JSON test case spec> <cert priv> <cert> [<turnover counter size>]
	       ./test_verify.py closed <JSON test case spec> <key priv> <pub key> [<turnover counter size>]
	       ./test_verify.py multi <key priv> <cert> <pub key> <turnover counter size 1>,... <group label> <JSON test case spec 1>...

This script works similarly to `run_test.py`. However, instead of generating the
DEP and crypto container specified in the JSON specification file as files, it
only generates them in memory and immediately calls the verification functions.

In addition to the standard elements the reference implementation uses in their
JSON test specification, this tool also understands the `expectedException` and
the `exceptionReceipt` elements which allow to specify an exception that the
verification functions must raise when verifying the generated DEP and on which
receipt this exception must occur. Furthermore, each receipt in the
`cashBoxInstructionList` may be extended with an `override` element, which
allows to change certain values of the receipt during the generation. For
details, see the `CashRegister.receipt()` function in `cashreg.py` or the test
cases in `tests`.

As opposed to `run_test.py`, `test_verify.py` only takes one key pair and reuses
it for all signature devices a test requires.

The `multi` mode allows the user to specify multiple comma-separated turnover
counter sizes and multiple JSON test specification files as the last parameters.
It will run each specified test as both open and closed system for each of the
given turnover counter sizes. This mode requires both a certificate and a public
key file. It will also recognize the `closedSystem` element in the test
specification. If it is present, the script will only execute the test as a
closed system (if it is `True`) or an open system (if it is `False`). This
allows for tests that are specific to open/closed systems.

verify_receipt.py
-----------------
	Usage: ./verify_receipt.py <format> <key store> [<receipt string>]

This script verifies receipts. The used certificates or public keys must be
available in the given key store. The formats `jws`, `qr`, `ocr`, `url` and
`csv` are supported. If `receipt string` is given, the receipt from the command
line is verified, otherwise the script reads and verifies receipts from stdin.
If the verification of a receipt fails the script prints an error message
indicating the line where the error occurred and what went wrong. Before
terminating it will also print a summary showing how many of the given receipts
were correct.

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

img_decode.py
-------------
	Usage: ./img_decode.py <image file>...

This script reads all image files given on the command line and extracts all QR
codes contained.

cert_extract.py
---------------
	Usage: ./cert_extract.py <output dir>

This script reads a JSON DEP from stdin, extracts all certificates from the
`Signaturzertifikat` and `Zertifizierungsstellen` elements and saves them in the
specified output directory. The output files are in PEM format and the file
names are of the form `<hex certificate serial>.crt`.

rktool.py
---------
This script provides a GUI to access some of the functionality provided by the
previously mentioned tools. It provides interfaces to manage key stores, verify
DEP files and import and verify single receipts from various sources.
