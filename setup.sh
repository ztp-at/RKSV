#!/bin/bash

openssl ecparam -name prime256v1 -genkey -out cert.key
openssl req -new -x509 -key cert.key -out cert.crt
openssl x509 -noout -pubkey -in cert.crt > cert.pub

dd if=/dev/urandom bs=1 count=32 | base64 > aesBase64.txt
