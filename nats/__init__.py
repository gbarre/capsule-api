import re
import json
import logging
import datetime
import base64
import socket
from pynats import NATSClient, NATSInvalidSchemeError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from models import webapp_nats_schema, capsule_nats_schema
from models import addon_schema, crons_schema
import ssl
from sqlalchemy.orm.exc import ObjectDeletedError


class NATSNoEchoClient(NATSClient):
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
            options["user"] = self._conn_options.username  # pragma: no cover
            options["pass"] = self._conn_options.password  # pragma: no cover
        elif self._conn_options.username:  # pragma: no cover
            options["auth_token"] = self._conn_options.username

        self._send(b"CONNECT", json.dumps(options))

    def connect(self) -> None:
        sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)

        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if self._socket_options["keepalive"]:  # pragma: no cover
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        self._socket = sock

        sock.settimeout(self._socket_options["timeout"])
        sock.connect((self._conn_options.hostname, self._conn_options.port))

        self._socket_file = sock.makefile("rb")

        scheme = self._conn_options.scheme

        if scheme == "nats":
            self._try_connection(tls_required=False)
        elif scheme == "tls":  # pragma: no cover
            self._try_connection(tls_required=True)
            self._connect_tls()
        else:  # pragma: no cover
            raise NATSInvalidSchemeError("got unsupported URI "
                                         f"scheme: {scheme}")

        self._send_connect_command()
        if self._conn_options.verbose:  # pragma: no cover
            OK_RE = re.compile(rb"^\+OK\s*\r\n")
            self._recv(OK_RE)

    def _connect_tls(self) -> None:  # pragma: no cover
        ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        if not self._conn_options.tls_verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        # HACK: replace cafile by cadata
        if self._conn_options.tls_cacert is not None:
            ctx.load_verify_locations(cadata=self._conn_options.tls_cacert)

        if self._conn_options.tls_client_cert is not None and \
           self._conn_options.tls_client_key is not None:
            ctx.load_cert_chain(
                certfile=self._conn_options.tls_client_cert,
                keyfile=self._conn_options.tls_client_key,
            )

        hostname = self._conn_options.hostname
        if self._conn_options.tls_hostname is not None:
            hostname = self._conn_options.tls_hostname

        self._socket = ctx.wrap_socket(self._socket, server_hostname=hostname)
        self._socket_file = self._socket.makefile("rb")


class NATS(object):
    client = None
    logger = None

    SUBJECT = 'capsule.>'

    _delimiter = b"^"

    def __init__(self, app=None):
        if app is not None:
            self.init_app(app)  # pragma: no cover

    # def __del__(self):
    #     if self.client is not None:
    #         self.client.close()

    def init_app(self, app):
        self.client = NATSNoEchoClient(
            url=app.config['NATS_URI'],
            name=app.config['APP_NAME'],
            tls_cacert=app.config['NATS_CA_CERT'],
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
        self.client.subscribe(subject, callback=callback, queue="capsule-api")

    def publish(self, subject, signed_payload):
        self.logger.debug(f"payload {signed_payload} published on {subject}.")
        try:
            self.client.publish(subject, payload=signed_payload)
        except (BrokenPipeError, OSError):  # pragma: no cover
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
        json_bytes = bytes(json.dumps(res), 'utf-8')

        private_key = serialization.load_pem_private_key(
            __class__._PRIVATE_KEY.encode('utf8'),
            password=None,
            backend=default_backend(),
        )

        # FIXME: PKCS1v15 is deprecated
        #        PSS is recommended for new protocols signature
        # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/?highlight=sign#signing
        signature = private_key.sign(
            json_bytes,
            padding.PKCS1v15(),
            # padding.PSS(
            #     mgf=padding.MGF1(hashes.SHA256()),
            #     salt_length=padding.PSS.MAX_LENGTH
            # ),
            hashes.SHA256(),
        )
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
        now = datetime.datetime.now()
        if now > (capsule.no_update + datetime.timedelta(hours=24)) and\
           capsule.webapp is not None:
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

        webapp_data = webapp_nats_schema.dump(webapp)
        capsule_data = capsule_nats_schema.dump(capsule)

        data = {
            "authorized_keys": [],
            "crons": crons_schema.dump(capsule.webapp.crons),
            "env": webapp_data['env'],
            "fqdns": capsule_data['fqdns'],
            "id": webapp_data['id'],
            "name": capsule_data['name'],
            "opts": webapp_data['opts'],
            "runtime_id": webapp_data['runtime_id'],
            "size": capsule_data['size'],  # tiny, small... (for k8s driver)
            "uid": capsule_data['uid'],
            "volume_size": webapp_data['volume_size'],  # GB (for filer driver)
        }
        tls_opts = [
            'tls_crt',
            'tls_key',
            'enable_https',
            'force_redirect_https',
            'certificate',
        ]
        for k in tls_opts:
            if k in capsule_data:
                data[k] = capsule_data[k]

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

        addon_data = addon_schema.dump(addon)
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
    def build_data_ids(obj_array):  # pragma: no cover
        ids = []
        for obj in obj_array:
            try:
                ids.append(str(obj.id))
            except ObjectDeletedError:
                pass

        return {"ids": ids}
