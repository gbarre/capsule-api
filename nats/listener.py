import os
import json
import threading
from models import capsule_verbose_schema
from models import WebApp, webapp_schema
from models import AddOn, addon_schema
from sqlalchemy import orm, create_engine
from app import nats
from json.decoder import JSONDecodeError
from ast import literal_eval
from Crypto.PublicKey import RSA
from Crypto.Signature.PKCS1_v1_5 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import base64


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

        # TODO: implements nats listening protocol
        origin_subject = msg.subject

        if not msg.is_msg_valid:
            nats.logger.debug(f"Message on subject {origin_subject} discarded because {msg.error}: {msg.payload}")
            return

        data_json = msg.json['data']
        query_id = data_json['id']

        if "capsule.webapp" in msg.subject:
            try:
                # get capsule from the webapp id
                webapp = session.query(WebApp).get(query_id)
                webapp_data = webapp_schema.dump(webapp).data
                webapp_data["env"] = literal_eval(webapp_data["env"])

                capsule = webapp.capsule
                capsule_data = capsule_verbose_schema.dump(capsule).data

                # build data to publish
                data = {
                    "authorized_keys": [],  # to build
                    "capsule-id": str(capsule.id),
                    "name": capsule.name,
                    "owners": [],  # to build
                    "webapp": webapp_data,
                }
            except Exception:
                # TODO: send deleted message
                # nats.publish_error(
                #     origin_subject,
                #     'not found',
                #     f"webapp '{query_id}' has not been found.")
                return

            # continue building data
            for sshkey in capsule_data['authorized_keys']:
                data['authorized_keys'].append(sshkey['public_key'])

            for owner in capsule_data['owners']:
                for sshkey in owner['public_keys']:
                    data['authorized_keys'].append(sshkey['public_key'])
                data['owners'].append(owner['name'])

            # publish data
            nats.publish(origin_subject, data)

        elif "capsule.addon" in msg.subject:
            try:
                # get capsule from the addon id
                addon = session.query(AddOn).get(query_id)
                addon_data = addon_schema.dump(addon).data
                addon_data["env"] = literal_eval(addon_data["env"])
                addon_data.pop('capsule_id')

                capsule = addon.capsule
                capsule_data = capsule_verbose_schema.dump(capsule).data

                # build data to publish
                data = {
                    "capsule-id": str(capsule.id),
                    "name": capsule.name,
                    "owners": [],  # to build
                    "addon": addon_data,
                }
            except Exception:
                # TODO: send deleted message
                # nats.publish_error(
                #     origin_subject,
                #     'not found',
                #     f"addon '{query_id}' has not been found.")
                return

            for owner in capsule_data['owners']:
                data['owners'].append(owner['name'])

            # publish data
            nats.publish(origin_subject, data)
        else:
            nats.publish_error(
                origin_subject,
                'invalid',
                'nothing to be done.'
            )

    def run(self):
        nats.logger.info('NATS listener waiting for incoming messages.')
        nats.client.wait()


class NATSDriverMsg:

    required_fields = [
        'from',
        'to',
        'message',
        'data',
        'time',
    ]

    def __init__(self, nats_msg):
        self.subject = nats_msg.subject
        self.payload = nats_msg.payload
        # print(self.payload)
        self._is_msg_valid()

    def _is_msg_valid(self):

        self.is_msg_valid = True
        self.error = None

        index = self.payload.find(b'^')

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

        for field in __class__.required_fields:
            if field not in self.json:
                self.is_msg_valid = False
                self.error = f'Key "{field}" is required in JSON'
                return

        if not(isinstance(self.json['data'], dict)
           and 'id' in self.json['data']):
                self.is_msg_valid = False
                self.error = 'Data value must be an object with the key "id"'
                return

    def create_response(self):
        # {
        #     "from": "api",
        #     "to": "k8s",
        #     "message": "absent", # (or present)
        #     "data": {
        #         "id": "652eaa13-adae-4717-b79a-06a99ac407ed",
        #     },
        #     "timestamp": XXX
        # }
        json = {
            "from": "api",
            "to": self.json['data']['from'],
            #TODO : complete
        }


        return


def create_nats_listener(app):
    nats.init_app(app)
    nats_listener = NATSListener()
    return nats_listener
