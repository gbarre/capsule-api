import json
from pynats import NATSClient


class NATSCustomClient(NATSClient):
    # HACK: We need to mask this method in order to disable the echo
    def _send_connect_command(self):
        options = {
            "name": self._conn_options["name"],
            "lang": self._conn_options["lang"],
            "protocol": self._conn_options["protocol"],
            "version": self._conn_options["version"],
            "verbose": self._conn_options["verbose"],
            "pedantic": self._conn_options["pedantic"],
            "echo": self._conn_options["echo"],
        }

        if self._conn_options["username"] and self._conn_options["password"]:
            options["user"] = self._conn_options["username"]
            options["pass"] = self._conn_options["password"]
        elif self._conn_options["username"]:
            options["auth_token"] = self._conn_options["username"]

        self._send(b"CONNECT", json.dumps(options))


# TODO: SSL
class NATS(object):
    def __init__(self, app=None):
        self.client = None
        if app is not None:
            self.init_app(app)

    # FIXME: exceptions at the end
    def __del__(self):
        if self.client is not None:
            self.client.close()

    def init_app(self, app):
        self.client = NATSClient(
            url=app.config['NATS_URI'],
            name=app.config['APP_NAME'],
            verbose=True,
        )
        self.client._conn_options['echo'] = False
        self.client.connect()
        app.extensions['nats'] = self