from tests.utils import api_version
from app import oidc
from unittest.mock import patch
import pytest
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


import base64
import datetime
import json


class TestNats:

    @staticmethod
    def sign_message(data, invalid=False):

        # WARNING: This key is for dev only, not used in production
        private_key = """
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4MUnDktq5JQKsxrOFzED71YRp0AZPWqDe0BmKhRz1rE5oKlM
2p9FtRpe+eWuLdRIerRZ/8lqX3hC/HJ0YjzC9iL+YC4SNOecIBw5wW43r1seLfSm
YkL2N5lf4R1mVNWjMwjboIKKzDbe9uDy6NCgKwUg1/aK2gD5A3aepkZugVOm+trJ
RLoOusCuxSNbHPyWD7g65WUHY2p+i/eU+R230UvLAnBSl5Q+UuaA8ogH8zwAXpHr
qrc1rDfSMEM9RBY6FbH9LTHYVNvR9QVihEmaLJ9oIrBNq28kyED0d20gh0n+y1vn
yhISNQPtMGVhdX4KTyKD7epGN4msg6KGKm+TuQIDAQABAoIBACIciZLXyz8pYH5S
ARjv7WLzMvao+auicJXR7i9Qr0vT1aUWTH2ZUmDrwaI3QzndT6qfmFEDZkta2v+o
9xS5l/T21pgOJeE1jTIqVnGOopDQSUI8MMwU0X0an7xwU8loKr5iB8LSTPI1GZ1q
AjNnBgfBXXypA+WV5DSsWeNuKPMjUA8W4S/kFPemeXsstZjowMKTAQVWvGDuXWq6
/XDOYNgbRZ7N6b9C+XVGfD4rTdjycsbZubvJIWfGTc1aEdkf6LnThBxdKs8rnb78
bp3DXjcBbKOQDVBefuTe4mLDHBVxU0x6cNTWFKBdVwnZmDAxauGLgPCa5tZ4Alx6
CsBUUMkCgYEA9MZOM3zaUcp7p2PJa61SznC7ORtc7Q8x371Lgxk0RryzEMwY4juy
ohft1Ni+YLwhLsMM2i068uLikVI+tz0fv7WzRIFq4GOSGTzIBQowjF2YL/EDWuh6
YnNQhZsIHXxOzIiM4snuOvT+E0SLJIKoYRvRSk95Hxux8qWKMQpK9/8CgYEA6xP9
rNK0AtpAXd9QInXvO2mPa7jYIfTQNsspQobO41leQWQ4b1nAivqS6abMLNh7Ccm7
7cbsF4WLQ8JGOuPcbxutcHNTD7d3ncf8xUBkNl0d4QQz5qdEDd3F+5xec9EinAB1
03Ij5/gOuIhuperqym4yvNVfgpnxIoKBXhK7NEcCgYBDWgGQl003bkDCGWoF7+Y2
GbzahNX4ANNXXi3V/+xrfmbDO3WpYoXPpkfx5kXUNk/nHxJ9Qi7TQGzZUckiAHao
+KVAN2AiKCO+QARFpr0fEm3a2zVyIT/zsQk6CiOcgWTpULV7fdbIcDstMBIdVLpi
JhZbnSyVy7gWLUiuH8frHwKBgQC9gJULn6NrdUNUKTQxQ38CFvt97DmXTgIXWbk+
Huxiy+U2s7Lm2KRlpM+PuV14fV7aKhzr9mLWJ1p32gHBcXR+wQIU13LLBaxQrinv
XRQr2u6+OSQZuRccUn5KceiWVq4esiRJuwaE9ivvyFPiPrjdTO5r2VowLyb7Gddt
3Y25+wKBgC7ILXVv05sbEDXszauV4wMqplFre28h8m4oL/ALI7thH1T3LBe9IUBq
4jiC+7C510ZIxRN8YaNSXKT3U9hmbpbtm5PgpBLIc/wqD/Yu6u/0yvsd8Ue8O5Co
h4kCbzDGKP8Jy0CMwq7srJqFWwTX7ab4Ga0srpG3JfHR11LgwUuG
-----END RSA PRIVATE KEY-----"""

        invalid_priv_key = """-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAzmWPf8G41TOnWk/R
+tw5QO6KHCEV0RhpfvdX5BOf/yWrqzpbkDZtkxTPMAfHmyQcKNc3i74b26RDIg+A
EOqiRwIDAQABAkALkhH7XYbZHO4y1+qzn4juJPFFJm2srSus3Hzm4lrD2OUAhOaD
UHB6d4GBsERDjQMd1mcB+PBoiaeT8ba+06XRAiEA7EFYBBQJI9ZTuPfOjwm9i4l2
lUHacUaGcDfJE8m1+UsCIQDfpWWLc1S9nqdyZCMRAMw/4BKskzH1dDlE8AnBG/o5
dQIhAKmAyFFEvroDj9XplT1y05dFbNrxgHQ9ET96Br43vmO5AiAqDkw+IP36em86
j6IYfHHsQRLB6Rwn8Cck047CBaTUUQIhALQ3dUZNfejgWkDzaNGr1EzIOazP+Y2f
Nuada5lLL1eq
-----END PRIVATE KEY-----"""

        json_bytes = bytes(json.dumps(data), 'utf-8')

        if invalid:
            key = invalid_priv_key.encode('utf8')
        else:
            key = private_key.encode('utf8')

        priv_key = serialization.load_pem_private_key(
            key,
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

        return response.decode('utf-8')

    # Delete a capsule to publish webapp & addon absent
    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_delete_capsule(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.superadmin_user):

            # Get the capsule id
            capsule_id = str(db.capsule1.id)
            # Delete this capsule
            testapp.delete(
                api_version + "/capsules/" + capsule_id,
                status=204
            )

    # Add sshkey to publish webapp present
    def test_create_webapp(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            _sshkey_input = {
                "public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDVbtGe1p6"
                              "vAjwizqEiO8EY5K3jyB7NoBT+gDREp6TcimUMJzsWryJamp"
                              "X7IqDpkC7I2/Y7oiUudVR97Q6H//IckCJetaD/yONkqzRCx"
                              "CoQz+J0JWlMZsS/MmIy6BHDrLYB6KBZ4zk6exxbxcanJnz2"
                              "fHahom8GE57l9khYgm3WLGi+v3ofb6ZsT6BrR8eXRpb6wJ6"
                              "HcghGRwWg7+M6IMqZdprvzGomc7UO3fPmQXf3KF9ZlelNCB"
                              "sczD4qrYshiScVqmWmo2jePTDESWaaP3jlqz7EkvfxukAuT"
                              "m2spohtmVs+iwxOTvEwP3o7ucfp/o7QRYPqL/OPXAN8pjzf"
                              "8zZ2 toto@input"
            }

            testapp.post_json(
                api_version + "/sshkeys",
                _sshkey_input,
                status=201
            )

    # Add addon to publish webapp present
    def test_create_addon(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            _addon_input = {
                "description": "Un redis sur la capsule",
                "name": "redis-1",
                "runtime_id": str(db.runtime2.id),
            }

            testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/addons',
                _addon_input,
                status=201
            )

    def test_bad_state_request(self, app, db):
        data = {
            "from": "k8s",
            "to": "api",
            "state": "?toto",
            "data": {
                "id": "1234"
            },
            "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        signed_message = self.sign_message(data)
        cmd = f"./dev-tools/nats-basic-pub -s nats://localhost:4222 " \
              f"'capsule.webapp' '{signed_message}'"

        os.popen(cmd)

    def test_bad_subject_request(self, testapp, db):
        data = {
            "from": "k8s",
            "to": "api",
            "state": "?status",
            "data": {
                "id": "1234"
            },
            "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        signed_message = self.sign_message(data)
        cmd = f"./dev-tools/nats-basic-pub -s nats://localhost:4222 " \
              f"'capsule.toto' '{signed_message}'"

        os.popen(cmd)

    def test_invalid_sign_request(self, testapp, db):
        data = {
            "from": "k8s",
            "to": "api",
            "state": "?status",
            "data": {
                "id": "1234"
            },
            "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        signed_message = self.sign_message(data, invalid=True)
        cmd = f"./dev-tools/nats-basic-pub -s nats://localhost:4222 " \
              f"'capsule.webapp' '{signed_message}'"

        os.popen(cmd)

    def test_valid_webapp_status_request(self, testapp, db):
        data = {
            "from": "k8s",
            "to": "api",
            "state": "?status",
            "data": {
                "id": str(db.webapp1.id)
            },
            "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        signed_message = self.sign_message(data, invalid=True)
        cmd = f"./dev-tools/nats-basic-pub -s nats://localhost:4222 " \
              f"'capsule.webapp' '{signed_message}'"

        os.popen(cmd)
