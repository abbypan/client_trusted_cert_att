#!/bin/bash

openssl ecparam -genkey -name prime256v1 -noout -out t_priv.pem
openssl ec -in t_priv.pem -pubout -out t_pub.pem

openssl req -new -key t_priv.pem -out t.csr -sha256 -subj "/C=CN/ST=Anhui/L=Hefei/O=ATTESTER/OU=ATTESTER/CN=someatt.com" -config t.cnf
openssl req -verify -in t.csr -text
openssl x509 -req -in t.csr -signkey t_priv.pem -out t.crt -sha256 -extfile t_ext.cnf
openssl x509 -text -in t.crt

openssl x509 -pubkey -in t.crt -noout | openssl ec -pubin -outform DER -out t_read_pub.der
openssl dgst -sha256 -hex t_read_pub.der
