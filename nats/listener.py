import os
import json
import threading
from models import capsule_verbose_schema
from models import WebApp, webapp_schema
from models import AddOn, addon_schema
from sqlalchemy import orm, create_engine
from sqlalchemy.exc import StatementError
from app import nats
from json.decoder import JSONDecodeError
from ast import literal_eval
from Crypto.PublicKey import RSA
from Crypto.Signature.PKCS1_v1_5 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import base64
import datetime


# TODO: Configuration must be unified
session_factory = orm.sessionmaker(
    bind=create_engine('{driver}://{user}:{passw}@{host}:{port}/{db}'.format(
        driver='mysql+pymysql',
        user='root',
        passw=os.environ.get('MYSQL_ROOT_PASSWORD'),
        host='localhost',
        port=30306,
        db=os.environ.get('MYSQL_DATABASE'),
    )))
session = orm.scoped_session(session_factory)


class NATSListener(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        # TODO: make subscriptions
        nats.subscribe(nats.SUBJECT, callback=self.listen)
        nats.logger.info('NATS listener initialized.')

    @staticmethod
    def listen(msg):

        msg = NATSDriverMsg(msg)

        origin_subject = msg.subject

        if not msg.is_msg_valid:
            nats.logger.debug(
                f"Message on subject {origin_subject} "
                "discarded because {msg.error}: {msg.payload}")
            return

        data_json = msg.json['data']
        query_id = data_json['id']

        if "capsule.webapp" in msg.subject:
            try:
                webapp = session.query(WebApp).get(query_id)
            except StatementError:
                msg.publish_response(data=None)
                return

            try:
                capsule = webapp.capsule
            except AttributeError:
                msg.publish_response(data=None)
                return

            webapp_data = webapp_schema.dump(webapp).data
            capsule_data = capsule_verbose_schema.dump(capsule).data

            if 'env' in webapp_data:
                webapp_data['env'] = literal_eval(webapp_data['env'])
            else:
                webapp_data['env'] = {}

            data = {
                "authorized_keys": [],
                "env": webapp_data['env'],
                "fqdns": webapp_data['fqdns'],
                "id": query_id,
                "name": capsule.name,
                "runtime_id": webapp_data['runtime_id'],
                "uid": capsule.uid,
            }
            for k in ['tls_crt', 'tls_key', 'tls_redirect_https']:
                if k in webapp_data:
                    data[k] = webapp_data[k]

            for sshkey in capsule_data['authorized_keys']:
                data['authorized_keys'].append(sshkey['public_key'])

            for owner in capsule_data['owners']:
                for sshkey in owner['public_keys']:
                    data['authorized_keys'].append(sshkey['public_key'])

            msg.publish_response(data=data)

        elif "capsule.addon" in msg.subject:
            try:
                addon = session.query(AddOn).get(query_id)
            except StatementError:
                msg.publish_response(data=None)
                return

            try:
                capsule = addon.capsule
            except AttributeError:
                msg.publish_response(data=None)
                return

            addon_data = addon_schema.dump(addon).data
            capsule_data = capsule_verbose_schema.dump(capsule).data
            if 'env' in addon_data:
                addon_data['env'] = literal_eval(addon_data['env'])
            else:
                addon_data['env'] = {}
                addon_data.pop('capsule_id')

            data = {
                "env": webapp_data['env'],
                "id": query_id,
                "name": capsule.name,
                "runtime_id": webapp_data['runtime_id'],
                "opts": webapp_data['opts'],
                "uri": webapp_data['uri'],
            }

            msg.publish_response(data=data)

        else:
            nats.logger.error(f"{origin_subject}: invalid subject.")

    def run(self):
        nats.logger.info('NATS listener waiting for incoming messages.')
        nats.client.wait()


class NATSDriverMsg:

    _required_fields = [
        'from',
        'to',
        'state',
        'data',
        'time',
    ]

    _state_answer = "?status"
    _delimiter = b"^"

    def __init__(self, nats_msg):
        self.subject = nats_msg.subject
        self.payload = nats_msg.payload
        self._is_msg_valid()

    def _is_msg_valid(self):

        self.is_msg_valid = True
        self.error = None

        index = self.payload.find(__class__._delimiter)

        if index < 0:
            self.is_msg_valid = False
            self.error = 'Message is not well signed'
            return

        self.signature = self.payload[:index]
        self.json_bytes = self.payload[index+1:]

        try:
            self.json = json.loads(self.json_bytes)
        except JSONDecodeError:
            self.json = None
            self.is_msg_valid = False
            self.error = 'Invalid JSON structure'
            return

        # TODO: import public_key from config
        # WARNING: This public key is an example
        public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCZE2XzAAHwtcG4tWn"\
                     "bnmtu4N5AQOJGwcQ6q1T24tepHTBFTZub2gr0MUYeRQq46tZjnVYAch"\
                     "oG5CsrVns9wAIgLku9XqwQFaCftG+Jwn3HlXImS4hq9w9MhXjXakbyG"\
                     "N+ghrMECxjQQPfnrKNLZHLm5Dwwcr38V/Go97s/zhZ7+G9cSgIY1NvK"\
                     "bImueOneOoA2xMjJC5NO3DQc+1VAAP+2D0ikzNCKfO7dWnornwUcYHD"\
                     "GtsgDRAkkBvxAlhcA0hFOciWkGwEogLcy3dEsAvTTWQO2w5qBDnWqEn"\
                     "kojCMPxI15MhrR3mbc4bny+H8pVQ/00bSBWRJZeOlCNU9CHP6od9thy"\
                     "3CMQM5xka0aHfi0O38QLOtEEm+h+A1LONb8hMGgNznw2TXHcZCrIvDk"\
                     "KnWXYhTPzJslNonf9pYIfqyqdjZPPvQVLZL9xt/UdGnNVojoy+RQEYP"\
                     "xX4r9rteY8XTkVKHZHLn0pCfAqwbF6hAwmAQy1AX9sFdlWT5G757KMM"\
                     "s= olecam@macbook-pro-1.home"

        pubkey = RSA.importKey(public_key)
        verifier = PKCS115_SigScheme(pubkey)

        signature = base64.b64decode(self.signature)
        hashed_json = SHA256.new(self.json_bytes)

        if not verifier.verify(hashed_json, signature):
            self.is_msg_valid = False
            self.error = 'Invalid signature'
            return

        if not isinstance(self.json, dict):
            self.is_msg_valid = False
            self.error = 'JSON must be an object'
            return

        for field in __class__._required_fields:
            if field not in self.json:
                self.is_msg_valid = False
                self.error = f'Key "{field}" is required in JSON'
                return

        if self.json["state"] != __class__._state_answer:
            self.is_msg_valid = False
            self.error = f'Value of state is not valid: {self.json["state"]}'
            return

        if not(isinstance(self.json['data'], dict)
           and 'id' in self.json['data']):
            self.is_msg_valid = False
            self.error = 'Data value must be an object with the key "id"'
            return

    def publish_response(self, data):
        if data is None:
            query_id = self.json['data']['id']
            data = {"id": query_id}
            state = "absent"
        else:
            state = "present"
        self.generate_response(state=state, data=data)
        nats.publish(self.subject, self.response)

    def generate_response(self, state, data):
        res = {
            "from": "api",
            "to": self.json['from'],
            "state": state,
            "data": data,
            "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

        # TODO: private must be provided from config.
        # WARNING: This private key is an example
        private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIG4wIBAAKCAYEAmRNl8wAB8LXBuLVp255rbuDeQEDiRsHEOqtU9uLXqR0wRU2b
m9oK9DFGHkUKuOrWY51WAHIaBuQrK1Z7PcACIC5LvV6sEBWgn7RvicJ9x5VyJkuI
avcPTIV412pG8hjfoIazBAsY0ED356yjS2Ry5uQ8MHK9/FfxqPe7P84We/hvXEoC
GNTbymyJrnjp3jqANsTIyQuTTtw0HPtVQAD/tg9IpMzQinzu3Vp6K58FHGBwxrbI
A0QJJAb8QJYXANIRTnIlpBsBKIC3Mt3RLAL001kDtsOagQ51qhJ5KIwjD8SNeTIa
0d5m3OG58vh/KVUP9NG0gVkSWXjpQjVPQhz+qHfbYctwjEDOcZGtGh34tDt/ECzr
RBJvofgNSzjW/ITBoDc58Nk1x3GQqyLw5Cp1l2IUz8ybJTaJ3/aWCH6sqnY2Tz70
FS2S/cbf1HRpzVaI6MvkUBGD8V+K/a7XmPF05FSh2Ry59KQnwKsGxeoQMJgEMtQF
/bBXZVk+Ru+eyjDLAgMBAAECggGAaVQ+t1lO/HmkZdt2jqbQV8glReMfj/5ubsxL
t2HZcUVjXJyNMU10chihndx2B02X3Y16iu34WLuRtM1aGeBP1iLk/NXy4VJwZtP6
V7lbYQTFOfKJWMjNXyMMRnWbgaR54/Qro+Ga3lmF+4UAC7V/lr5/Z/rcHZHJ+DEW
SE4fjIgi4EcQcFOvNPdAOax7h+2LIaSAYE41u3Kr7TFHtLW7PmP/4V4JNPHITsmd
/Pv7wU3e6+0DbbPX8lFYK3zbMTZZn8OVkMNkpl0OQH7tWEA4GFeYT/rongHNxLLH
JT/JecDHPIHXSC2oNSPgTmAui1/Rz4mkd4kmnSQBeRsi4lmNgSum4bvwv7oAhW/B
e6BE3ltQhIzIf+Wsgc2Ab8gaRkysz0IqFOYQhyKltoJ1yZqYS71fHppykOKKDspt
Vmqgw3xqOVFhLGZC6kMplumpffQmSXxY763z+AzcfnzAFjQ2PUOJiJSfk08o0aFZ
OICmxYPmVZS73ZN/0U0EBEzM53ahAoHBAMi2k+o8tkH0j3NA69k0RxNNKO1C6Zlp
XXuefuEq/ACgysHiCf7O4JNUuT1TgFLrDb+2J4D7qg9eCDOCAIGwNFpGaTUkqyF3
rgKSM89EoERZ6T9e/MW0wbZlPf0hcJ8gAizg+X76oAzXOXHea+s88/l16c2NIdQn
F8lBUZM/ViTVopS73FW+ZdMF4grHs+Mhnn9ViAoulspHaDm1fu0yOZHrycPvTJLq
BHWJ/Q3jtA4rl6GmT/NnLuufbqc9aYuv8QKBwQDDPaL4c2TlgS2mOvy0o9DtQNVe
OwyPGBqoz1e2/8ogCdQdOV7jMGcq7GUaqv2gDkBz4sx6xEt0byTD5efq3mLMzePL
o8ylTfnoWf+ILwYvvhOvSrzyiYC2WjoKZCmi/iA2uBXoS2ctWtb4XkkDNk64trcO
4x79UdlGoqtNOyoYCJowvdWnIQVNAgP1SfPv7lmyyY2Wjk2BvQYpzg/5A351v+Iu
Z5vmEBuxe5GC4N45t72NFFamPsunT/O1yTcfKHsCgcEAmlFmIG5VYxh5Qo/jxbgf
/YMRuHn9yOnt6iHOQ6kc4A7AVZlJPhQpLp2xXqlYvGfkxkVy0gSsl+wgOhn18cBc
QBxqv2VV/gFaVLe8BdwprOPEJekOR6PWXDozEvAm+vFNOtwud6aSb8z6acYtC0xt
+JrkDBo6rDbyXtZNtfy4atGmktxtZ69f8oNPbCJm+HbcueI1Gj7/yL5mMBiPYid/
g+XZ1z+hjENI8mYJnig4Q7zYdHy+c9IdjSOjnAnnoHLBAoHANd4xst8TvYbQs4ae
5rA0GuHCfQdJxclewajDiMg2WnSbw5xqo8BdFqi2lI8M/zYvbknrJQw3zV5FBI/Q
VysYk21TJoKBGjLTetop+McQq+eDwt+aFkj97FIkpW1RV5lKBg7wbHExfIANw+Uv
u+Ul/yzagQ8FI9uLWUPUg7CJQqxM7pnR8xTXQ5IEyY6n8VEQCpY1rI6CsAMZSjuC
iLAAGjjhDPClQOq82VFAqp2kcsRRVjWAWsoEopsaoNNtk/k1AoHAba8MMo9L8E7Z
T6VyS+85gEC+9O7IsudhD5YJLLWDMDJ8A8WhcfVPh9B3I76QkaRJSgHqgC4dyWAU
BR540DoKefvN3DLtUzZZ9AL9a7bMr4HwLXyunW/ssmV7tZC9l0ipuSxLf+V/t5Hv
vgE7kFbp3J5D7NV1QWtYkd6kILUL4Jj7xAKQPdGAAA62WdpF2jQgYPfmAQJf46v/
b4h8/l1WOckrAcgdLn1EbYJzEeqglH1uy4DKYYR3ACde0KpAZHD9
-----END RSA PRIVATE KEY-----"""

        json_bytes = bytes(json.dumps(res), 'utf-8')
        json_hash = SHA256.new(json_bytes)
        priv_key = RSA.importKey(private_key)
        signer = PKCS115_SigScheme(priv_key)
        signature = signer.sign(json_hash)
        encoded_signature = base64.b64encode(signature)
        self.response = encoded_signature + __class__._delimiter + json_bytes


def create_nats_listener(app):
    nats.init_app(app)
    nats_listener = NATSListener()
    return nats_listener
