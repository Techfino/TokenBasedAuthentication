#
# Copyright (c) 2014-2017 Techfino, LLC
# 1900 Market Street, 8th Floor, Philadelphia, PA 19103, USA
# All Rights Reserved.
#
# This software is the confidential and proprietary information of Techfino LLC.
# ("Confidential Information") - You shall not disclose such Confidential Information
# without prior written permission.
#
# Script Description:
#  This script is the central library for webservices functions for Techfino SS 2.0
#

import oauth2 as oauth
import json
import requests
import time

url = "https://rest.netsuite.com/.../restlet.nl?script=X&deploy=Y"
token = oauth.Token(key="____________________________", secret="____________________________")
consumer = oauth.Consumer(key="____________________________", secret="____________________________")
http_method = "POST"
realm = "123456"  # NetSuite account id

# the JSON data to be sent to the RESTlet
payload = {
    name:value, 
    foo:bar,
    duck:hunt,
}

params = {
	'oauth_version': "1.0",
	'oauth_nonce': oauth.generate_nonce(),
	'oauth_timestamp': str(int(time.time())),
	'oauth_token': token.key,
	'oauth_consumer_key': consumer.key
}

req = oauth.Request(method=http_method, url=url, parameters=params)
signature_method = oauth.SignatureMethod_HMAC_SHA1()
req.sign_request(signature_method, consumer, token)
header = req.to_header(realm)
headery = header['Authorization'].encode('ascii', 'ignore')
headerx = {"Authorization": headery, "Content-Type": "application/json"}
print(headerx)
conn = requests.post(url, headers=headerx, data=json.dumps(payload))
print("Result: " + conn.text)
print(conn.headers)
