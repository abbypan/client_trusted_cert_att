#!/usr/bin/python

import sys
from jwcrypto import jwk,jws
from jwcrypto.common import json_decode
from OpenSSL.crypto import (load_certificate, dump_publickey, dump_certificate, X509, X509Name, PKey)
from OpenSSL.crypto import (TYPE_DSA, TYPE_RSA, FILETYPE_PEM, FILETYPE_ASN1)
from Crypto.Util.asn1 import (DerSequence, DerObject)
from Crypto.Hash import SHA256

trust_anchor = "301ebf87f32521272334d4bba965d48fccd0d3d999fd9f08c7bf21e7e5c28f54"

crtatt_f = "crtatt/example.json"
with open(crtatt_f, "r") as f:
   crtatt_js = f.read()
f.closed

crtatt = json_decode(crtatt_js)
#print(crtatt)

crt = load_certificate(FILETYPE_PEM, crtatt["header"]["x5c"])

subject_pubkey_der = dump_publickey(FILETYPE_ASN1, crt.get_pubkey())
h = SHA256.new()
h.update(subject_pubkey_der)
dgst_spk = h.hexdigest()

if(dgst_spk==trust_anchor):
        subject_pubkey_pem = dump_publickey(FILETYPE_PEM, crt.get_pubkey())
        pub_key = jwk.JWK.from_pem(subject_pubkey_pem, None)

        jwstoken_v = jws.JWS()
        jwstoken_v.deserialize(crtatt_js)

        res=jwstoken_v.verify(pub_key)
        
        if(res==None):
            payload_v = jwstoken_v.payload
            cache_f = open("crtatt/example.cache", "wb")
            cache_f.write(payload_v)
            cache_f.closed
