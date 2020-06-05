import json
import logging
from pynats import NATSClient


logger = logging.getLogger(__name__)


class NATSNoEchoClient(NATSClient):
    # HACK: We need to mask this method in order to disable the echo
    def _send_connect_command(self):
        options = {
            "name": self._conn_options["name"],
            "lang": self._conn_options["lang"],
            "protocol": self._conn_options["protocol"],
            "version": self._conn_options["version"],
            "verbose": self._conn_options["verbose"],
            "pedantic": self._conn_options["pedantic"],
            "echo": False,  # added by the method masking
        }

        if self._conn_options["username"] and self._conn_options["password"]:
            options["user"] = self._conn_options["username"]
            options["pass"] = self._conn_options["password"]
        elif self._conn_options["username"]:
            options["auth_token"] = self._conn_options["username"]

        self._send(b"CONNECT", json.dumps(options))


class NATS(object):
    client = None

    CAPSULE_SUBJECT = 'capsule'

    def __init__(self, app=None):
        if app is not None:
            self.init_app(app)

    def __del__(self):
        if self.client is not None:
            self.client.close()

    def init_app(self, app):
        self.client = NATSNoEchoClient(
            url=app.config['NATS_URI'],
            name=app.config['APP_NAME'],
        )
        self.client.connect()

    def subscribe(self, subject, *, callback):
        logger.debug(f"subscribed to {subject}.")
        self.client.subscribe(subject, callback=callback)

    def publish_capsule(self, json_payload):
        self._publish(self.CAPSULE_SUBJECT, json_payload)

    def _publish(self, subject, json_payload):
        logger.debug(f"payload {json_payload} published on {subject}.")
        self.client.publish(subject, payload=json.dumps(json_payload))


def create_nats_listener(app):
    nats.init_app(app)
    nats_listener = NATSListener()
    return nats_listener
