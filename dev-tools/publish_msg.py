from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


import os
import base64
import datetime
import json
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--state")
parser.add_argument("--data")
parser.add_argument("--nats")
parser.add_argument("--subject")

args = parser.parse_args()


res = {
    "from": "k8s",
    "to": "api",
    "state": args.state,
    "data": json.loads(args.data),
    "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
}

# WARNING: This key is for dev only, not used in production
private_key = """-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----"""

json_bytes = bytes(json.dumps(res), 'utf-8')
# json_hash = SHA256.new(json_bytes)
# priv_key = RSA.importKey(private_key)
# signer = pkcs1_15.new(priv_key)
# signature = signer.sign(json_hash)

priv_key = serialization.load_pem_private_key(
    private_key.encode('utf8'),
    password=None,
    backend=default_backend(),
)
signature = priv_key.sign(
    json_bytes,
    padding.PKCS1v15(),
    hashes.SHA256(),
)

encoded_signature = base64.b64encode(signature)
response = encoded_signature + b'^' + json_bytes

msg = response.decode('utf-8')
cmd = f"./nats-basic-pub -s nats://{args.nats} '{args.subject}' '{msg}'"
os.system(cmd)
