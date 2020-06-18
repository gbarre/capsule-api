# import os
import json
import threading
from models import WebApp
from models import AddOn
from sqlalchemy import orm, create_engine
from sqlalchemy.exc import StatementError
from app import nats
from json.decoder import JSONDecodeError
from Crypto.PublicKey import RSA
from Crypto.Signature.PKCS1_v1_5 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import base64


class NATSListener(threading.Thread):

    def __init__(self, config):
        super().__init__(daemon=True)
        # TODO: make subscriptions
        nats.subscribe(nats.SUBJECT, callback=self.listen)
        nats.logger.info('NATS listener initialized.')
        self.init_session(config.SQLALCHEMY_DATABASE_URI)
        __class__.config = config

    def init_session(self, uri):
        session_factory = orm.sessionmaker(bind=create_engine(uri))
        __class__.session = orm.scoped_session(session_factory)

    @staticmethod
    def listen(msg):

        msg = NATSDriverMsg(msg, __class__.config)

        origin_subject = msg.subject

        if not msg.is_msg_valid:
            nats.logger.debug(
                f"Message on subject {origin_subject} "
                f"discarded because {msg.error}: {msg.payload}")
            return

        data_json = msg.json['data']
        query_id = data_json['id']

        if "capsule.webapp" in msg.subject:
            try:
                webapp = __class__.session.query(WebApp).get(query_id)
            except StatementError:
                # For instance the id is malformed.
                msg.publish_response(data=None)
                return

            try:
                capsule = webapp.capsule
            except AttributeError:
                # The id is well formed but no webapp with this capsule.
                msg.publish_response(data=None)
                return

            data = nats.build_nats_webapp_data(webapp, capsule)
            msg.publish_response(data=data)

        elif "capsule.addon" in msg.subject:
            try:
                addon = __class__.session.query(AddOn).get(query_id)
            except StatementError:
                msg.publish_response(data=None)
                return

            try:
                capsule = addon.capsule
            except AttributeError:
                msg.publish_response(data=None)
                return

            data = nats.build_nats_addon_data(addon, capsule.name)
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

    def __init__(self, nats_msg, config):
        self.subject = nats_msg.subject
        self.payload = nats_msg.payload
        self.config = config
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
        self.json_bytes = self.payload[index + 1:]

        try:
            self.json = json.loads(self.json_bytes)
        except JSONDecodeError:
            self.json = None
            self.is_msg_valid = False
            self.error = 'Invalid JSON structure'
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

        driver = self.json['from']
        # TODO: KeyError with unknown driver in config.
        public_key = self.config.get_pubkey_from_driver(driver)

        pubkey = RSA.importKey(public_key)
        verifier = PKCS115_SigScheme(pubkey)

        signature = base64.b64decode(self.signature)
        hashed_json = SHA256.new(self.json_bytes)

        if not verifier.verify(hashed_json, signature):
            self.is_msg_valid = False
            self.error = 'Invalid signature'
            return

        if self.json["state"] != __class__._state_answer:
            self.is_msg_valid = False
            self.error = f'Value of state is not valid: {self.json["state"]}'
            return

        j = self.json['data']
        if not(isinstance(j, dict) and 'id' in j):
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
        response = nats.generate_response(
            to=self.json['from'],
            state=state,
            data=data
        )
        nats.publish(self.subject, response)


def create_nats_listener(app, config):
    nats.init_app(app)
    nats_listener = NATSListener(config)
    return nats_listener
