#!/bin/bash

openssl ecparam -name prime256v1 -genkey -out cert.key
openssl req -new -x509 -key cert.key -out cert.crt

dd if=/dev/urandom bs=1 count=32 | base64 > aesBase64.txt
