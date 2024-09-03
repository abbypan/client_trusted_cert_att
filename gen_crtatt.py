#!/usr/bin/python

import sys
from jwcrypto import jwk,jws
from jwcrypto.common import json_encode

cert = "attester/t.crt"
with open(cert, "r") as f:
   cert_pem = f.read()
f.closed

header = json_encode({
        "alg": "ES256", 
        "x5c": cert_pem
        })


priv = "attester/t_priv.pem"
with open(priv, "rb") as f:
   priv_pem = f.read()
f.closed
priv_key = jwk.JWK.from_pem(priv_pem, None)
#print(priv_key)

payload = json_encode({
    "attid": "example",  
    "time": "2024-07-25 15:00:00",
    "dgstalg": "SHA256", 
    "content": [
        {
            "dom": [ "www.cmbc.com.cn", "*.baidu.com" ],
            "cadom": [ "globalsign.com", "! letsencrypt.org" ]
            }, 
        {
            "dom": [ "www.psbc.com", "www.hxb.com.cn", "www.cebbank.com" ],
            "cadom": [ "cfca.com.cn", "! letsencrypt.org" ]
            }, 
        {
            "dom": [ "www.spdb.com.cn", "www.icbc.com.cn", "www.citicbank.com", "www.cib.com.cn", "www.cgbchina.com.cn", "www.ccb.com", "www.boc.cn", "www.bankcomm.com", "www.abchina.com", "cmbchina.com", "bank.pingan.com", "*.alipay.com" ],
            "cadom": [ "digicert.cn", "digicert.com", "digicert-cn.com", "! letsencrypt.org" ]
            }, 
        { "dom" : [ "www.alipay.com" ],
         "pkdgst": [ "51f3f3f9cbaf62fadadd2593833daf09540f805488ae3ffd1f73505c7a6ca1f9" ]
         }
        ]
        })
jwstoken = jws.JWS(payload)

jwstoken.add_signature(priv_key, 
                       None, #alg
                       None, #protected
                       header 
                       )
sig = jwstoken.serialize()
#print(sig)

f = open("crtatt/example.json", "w")
f.write(sig)
f.close()
