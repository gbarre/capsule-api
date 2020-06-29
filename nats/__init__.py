import json
import logging
from pynats import NATSClient
import datetime
from Crypto.Hash import SHA256
import base64
from Crypto.Signature.PKCS1_v1_5 import PKCS115_SigScheme
from Crypto.PublicKey import RSA
from models import webapp_nats_schema, capsule_verbose_schema, addon_schema
import io
from pynats.exceptions import NATSReadSocketError


class NATSNoEchoClient(NATSClient):
    SHUT_RDWR = 2
    _CRLF_ = b"\r\n"

    # HACK: We need to mask this method in order to disable the echo
    def _send_connect_command(self):
        options = {
            "name": self._conn_options.name,
            "lang": self._conn_options.lang,
            "protocol": self._conn_options.protocol,
            "version": self._conn_options.version,
            "verbose": self._conn_options.verbose,
            "pedantic": self._conn_options.pedantic,
            "echo": False,  # added by the method masking
        }

        if self._conn_options.username and self._conn_options.password:
            options["user"] = self._conn_options.username
            options["pass"] = self._conn_options.password
        elif self._conn_options.username:
            options["auth_token"] = self._conn_options.username

        self._send(b"CONNECT", json.dumps(options))

    def close(self) -> None:
        self._socket.shutdown(self.SHUT_RDWR)
        self._socket_file.close()
        self._socket.close()

    def _readline(self, *, size: int = None) -> bytes:
        read = io.BytesIO()

        while True:
            # if self.IS_DECONNECTED:
            #     self.connect()
            line = self._socket_file.readline()
            if not line:
                raise NATSReadSocketError()
                # self.close()
                # self.IS_DECONNECTED = True

            read.write(line)

            if size is not None:
                if read.tell() == size + len(self._CRLF_):
                    break
            elif line.endswith(self._CRLF_):  # pragma: no branch
                break

        return read.getvalue()


class NATS(object):
    client = None
    logger = None

    SUBJECT = 'capsule.>'

    _delimiter = b"^"

    def __init__(self, app=None):
        if app is not None:
            self.init_app(app)

    # def __del__(self):
    #     if self.client is not None:
    #         self.client.close()

    def init_app(self, app):
        self.client = NATSNoEchoClient(
            url=app.config['NATS_URI'],
            name=app.config['APP_NAME'],
        )
        __class__._PRIVATE_KEY = app.config['PRIVATE_KEY']
        self.logger = logging.getLogger('NATS')
        self.logger.setLevel(getattr(logging, app.config['NATS_LOG_LEVEL']))

        formatter = logging\
            .Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)

        self.logger.addHandler(console_handler)
        self.client.connect()

    def subscribe(self, subject, *, callback):
        self.logger.debug(f"subscribed to {subject}.")
        self.client.subscribe(subject, callback=callback)

    def publish(self, subject, signed_payload):
        self.logger.debug(f"payload {signed_payload} published on {subject}.")
        try:
            self.client.publish(subject, payload=signed_payload)
        except BrokenPipeError:
            self.logger.error(f"payload {signed_payload} has not been "
                              f"published on {subject}.")

    @staticmethod
    def generate_response(to, state, data):
        res = {
            "from": "api",
            "to": to,
            "state": state,
            "data": data,
            "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

        private_key = __class__._PRIVATE_KEY

        json_bytes = bytes(json.dumps(res), 'utf-8')
        json_hash = SHA256.new(json_bytes)
        priv_key = RSA.importKey(private_key)
        signer = PKCS115_SigScheme(priv_key)
        signature = signer.sign(json_hash)
        encoded_signature = base64.b64encode(signature)
        return encoded_signature + __class__._delimiter + json_bytes

    def _publish_response_after_api_request(self, data, state, subject):
        signed_payload = self.generate_response(
            to="*",
            state=state,
            data=data
        )
        self.publish(subject, signed_payload)

    def publish_webapp_present(self, capsule):
        if capsule.webapp is not None:
            data = self.build_nats_webapp_data(capsule.webapp, capsule)
            self._publish_response_after_api_request(
                data,
                'present',
                "capsule.webapp"
            )

    def publish_webapp_absent(self, webapp_id):
        data = {"id": webapp_id}
        self._publish_response_after_api_request(
            data, 'absent', 'capsule.webapp'
        )

    @staticmethod
    def build_nats_webapp_data(webapp, capsule):

        webapp_data = webapp_nats_schema.dump(webapp).data
        capsule_data = capsule_verbose_schema.dump(capsule).data

        data = {
            "authorized_keys": [],
            "env": webapp_data['env'],
            "fqdns": webapp_data['fqdns'],
            "id": webapp_data['id'],
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

        return data

    def publish_addon_present(self, addon, capsule_name):
        data = self.build_nats_addon_data(addon, capsule_name)
        runtime_id = str(addon.runtime_id)
        self._publish_response_after_api_request(
            data,
            'present',
            f"capsule.addon.{runtime_id}"
        )

    def publish_addon_absent(self, addon_id, runtime_id):
        data = {"id": str(addon_id)}
        self._publish_response_after_api_request(
            data, 'absent', f"capsule.addon.{runtime_id}"
        )

    @staticmethod
    def build_nats_addon_data(addon, capsule_name):

        addon_data = addon_schema.dump(addon).data
        addon_data.pop('capsule_id')

        data = {
            "env": addon_data['env'],
            "id": addon_data['id'],
            "name": capsule_name,
            "runtime_id": addon_data['runtime_id'],
            "opts": addon_data['opts'],
            "uri": addon_data['uri'],
        }

        return data

    @staticmethod
    def build_data_ids(obj_array):
        ids = []
        for obj in obj_array:
            ids.append(str(obj.id))

        return {"ids": ids}
