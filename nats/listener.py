import time
import json
import base64
import threading
from models import WebApp
from models import AddOn
from sqlalchemy import orm, create_engine
from sqlalchemy.exc import OperationalError, StatementError
from app import nats
from json.decoder import JSONDecodeError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from pynats.exceptions import NATSReadSocketError


class NATSListener(threading.Thread):

    def __init__(self, config):
        super().__init__(daemon=True)
        nats.subscribe(nats.SUBJECT, callback=self.listen)
        nats.logger.info('NATS listener initialized.')
        self.init_session(config.SQLALCHEMY_DATABASE_URI)
        __class__.config = config

    def init_session(self, uri):
        session_factory = orm.sessionmaker(
            bind=create_engine(uri, pool_pre_ping=True)
        )
        __class__.session = orm.scoped_session(session_factory)

    @staticmethod
    def listen(msg):

        nats.logger.info('msg received')

        msg = NATSDriverMsg(msg, __class__.config)

        origin_subject = msg.subject

        if not msg.is_msg_valid:
            nats.logger.debug(
                f"Message on subject {origin_subject} "
                f"discarded because {msg.error}: {msg.payload}")
            return

        msg_state = msg.json['state']
        msg_invalid_subject = f"{origin_subject}: invalid subject."

        if msg_state == "?status":
            data_json = msg.json['data']
            query_id = data_json['id']

            if "capsule.webapp" in msg.subject:
                webapp = __class__.get_sqlalchemy_obj(
                    subj=origin_subject,
                    obj=WebApp,
                    query_id=query_id,
                )
                if webapp is None:
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
                addon = __class__.get_sqlalchemy_obj(
                    subj=origin_subject,
                    obj=AddOn,
                    query_id=query_id,
                )
                if addon is None:
                    return

                try:
                    capsule = addon.capsule
                except AttributeError:
                    msg.publish_response(data=None)
                    return

                data = nats.build_nats_addon_data(addon, capsule.name)
                msg.publish_response(data=data)

            else:
                nats.logger.error(msg_invalid_subject)

        elif msg_state == "?list":
            if "capsule.webapp" in msg.subject:
                webapps = __class__.get_sqlalchemy_obj(
                    subj=origin_subject,
                    obj=WebApp,
                )
                if webapps is None:
                    return

                data = nats.build_data_ids(webapps)
                msg.publish_response(data=data)
            elif "capsule.addon" in msg.subject:
                try:
                    runtime_id = msg.subject.split('.')[2]
                except IndexError:
                    nats.logger.error(msg_invalid_subject)
                    return

                addons = __class__.get_sqlalchemy_obj(
                    subj=origin_subject,
                    obj=AddOn,
                    runtime_id=runtime_id,
                )
                if addons is None:
                    return

                data = nats.build_data_ids(addons)
                msg.publish_response(data=data)
            else:
                nats.logger.error(msg_invalid_subject)

    @staticmethod
    def get_sqlalchemy_obj(subj, obj, query_id=None, runtime_id=None):
        result = None
        try:
            if query_id is not None:
                if len(query_id) == 36:
                    result = __class__.session.query(obj).get(query_id)
                else:
                    result = __class__.session.query(obj)\
                        .filter_by(name=query_id).first()
            elif runtime_id is not None:
                result = __class__.session.query(obj)\
                    .filter_by(runtime_id=runtime_id).all()
            else:
                result = __class__.session.query(obj).all()
        except OperationalError:
            nats.logger.error(f"{subj}: database unreachable.")
            __class__.session.rollback()
        except StatementError:
            nats.logger.error(f"{subj}: invalid id submitted.")

        return result

    def run(self):
        nats.logger.info('NATS listener waiting for incoming messages.')
        __reconnect = False
        while True:
            try:
                if __reconnect is True:
                    nats.client.connect()
                    nats.subscribe(nats.SUBJECT, callback=self.listen)
                    nats.logger.info("NATS reconnected.")
                    __reconnect = False
                nats.client.wait()
            except (NATSReadSocketError, ConnectionRefusedError):
                nats.client._socket_file.close()
                nats.client._socket.close()
                __reconnect = True
                nats.logger.error("NATS server is unreachable, "
                                  "try to reconnect in 5 seconds...")
                time.sleep(5)
                continue
        nats.client.close()


class NATSDriverMsg:

    _required_fields = [
        'from',
        'to',
        'state',
        'data',
        'time',
    ]

    _state_answer = ["?status", "?list"]
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
        public_key = serialization.load_pem_public_key(
            self.config.get_pubkey_from_driver(driver).encode('utf8'),
            backend=default_backend(),
        )

        signature = base64.b64decode(self.signature)
        try:
            public_key.verify(
                signature,
                self.json_bytes,
                padding.PKCS1v15(),
                # padding.PSS(
                #     mgf=padding.MGF1(hashes.SHA256()),
                #     salt_length=padding.PSS.MAX_LENGTH,
                # ),
                hashes.SHA256(),
            )
        except InvalidSignature:
            self.is_msg_valid = False
            self.error = 'Invalid signature'
            return

        if self.json["state"] not in __class__._state_answer:
            self.is_msg_valid = False
            self.error = f'Value of state is not valid: {self.json["state"]}'
            return

        j = self.json['data']
        if (self.json["state"] == "?status") and \
                not(isinstance(j, dict) and 'id' in j):
            self.is_msg_valid = False
            self.error = 'Data value must be an object with the key "id"'
            return

    def publish_response(self, data):
        if self.json["state"] == "?list":
            state = "list"
        else:
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
