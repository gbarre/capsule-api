from tests.utils import api_version, bad_id, unexisting_id, dict_contains
from app import oidc
from unittest.mock import patch
from models import webapp_schema
import json
import pytest
from nats import NATS


#
# DISCLAIMER : key and cert in this file are only used for tests
#              DO NOT USE THEM IN PRODUCTION ENVIRONMENT
class TestCapsuleWebapp:

    _webapp_input = {
        "env": {
            "HTTP_PROXY": "http://example.com:3128/",
            "HTTPS_PROXY": "https://example.com:3128/",
        },
        "fqdns": [
            {
                "name": "main.example.com",
                "alias": False
            },
            {
                "name": "sub.secondary.my-example.com",
                "alias": True
            },
        ],
        "opts": [
            {
                "field_name": "worker",
                "tag": "PHP",
                "value": "42"
            },
        ],
        "tls_redirect_https": False,
        "tls_key": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUJWZ0lCQURBTkJn"
                   "a3Foa2lHOXcwQkFRRUZBQVNDQVVBd2dnRThBZ0VBQWtFQXE3S3BqZnRh"
                   "R25uc0pNSCsKYmo4NnpLanJLMkNwMnVUYTJEYnZJYkN4UUlOTjFiNUJB"
                   "OUI0Zy8yQzQ4SzY3blNieGRKOFM3Ymp3Um5jdzg3aQpVSkFJSXdJREFR"
                   "QUJBa0VBbjlwL01jbEtZa3dSSjBmVjhoNjhSNzhjOUEzVEZoRHNEMUZW"
                   "NGkvM1Z1OWlMSHZHCkk1aVhwa0k4bFByQndTWEQ2alFNN2ViNFhMZmR3"
                   "ZTlHb3NUb0FRSWhBTkl1ODBleHRrMkxNcWNVQ3ZmQjJWcTcKQzJxNXFo"
                   "MFBLeDFVV3F6bjhuT0JBaUVBMFNBU1d3ZnQwSjZwbmc0ZUxLY05zSHBa"
                   "QTBOOTFJcTZUeFg3Y0lJSwovYU1DSUhWY1JmZDRZYVQyM3Jld1YxZDBa"
                   "RnRuS2I3VUlRck0xM1F2RDlxUVFTOEJBaUVBcnBSK25sNE5LNGI1CkJN"
                   "aTJhZ0ovekI4blpqRVd2N09jZTE5WGpBSVVHTThDSVFDWTlXcGlsQXZC"
                   "NVZoRm1tc1RBQkdGc2VkK0pubXIKVnkzTTBLRVNDdE1jN1E9PQotLS0t"
                   "LUVORCBQUklWQVRFIEtFWS0tLS0tCg==",
        "tls_crt": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUI0VENDQVl1Z0F3"
                   "SUJBZ0lVVUthalh3eTVMVGxzYnI2T3JvRE52T05JNWNBd0RRWUpLb1pJ"
                   "aHZjTkFRRUwKQlFBd1JURUxNQWtHQTFVRUJoTUNRVlV4RXpBUkJnTlZC"
                   "QWdNQ2xOdmJXVXRVM1JoZEdVeElUQWZCZ05WQkFvTQpHRWx1ZEdWeWJt"
                   "VjBJRmRwWkdkcGRITWdVSFI1SUV4MFpEQWVGdzB5TURBM01ETXhNalF5"
                   "TURkYUZ3MHlNREE0Ck1ESXhNalF5TURkYU1FVXhDekFKQmdOVkJBWVRB"
                   "a0ZWTVJNd0VRWURWUVFJREFwVGIyMWxMVk4wWVhSbE1TRXcKSHdZRFZR"
                   "UUtEQmhKYm5SbGNtNWxkQ0JYYVdSbmFYUnpJRkIwZVNCTWRHUXdYREFO"
                   "QmdrcWhraUc5dzBCQVFFRgpBQU5MQURCSUFrRUFxN0twamZ0YUdubnNK"
                   "TUgrYmo4NnpLanJLMkNwMnVUYTJEYnZJYkN4UUlOTjFiNUJBOUI0Cmcv"
                   "MkM0OEs2N25TYnhkSjhTN2Jqd1JuY3c4N2lVSkFJSXdJREFRQUJvMU13"
                   "VVRBZEJnTlZIUTRFRmdRVWFRVFIKTnJFenlYZjlhcWRMZU9BbFd6TmNP"
                   "d1V3SHdZRFZSMGpCQmd3Rm9BVWFRVFJOckV6eVhmOWFxZExlT0FsV3pO"
                   "YwpPd1V3RHdZRFZSMFRBUUgvQkFVd0F3RUIvekFOQmdrcWhraUc5dzBC"
                   "QVFzRkFBTkJBSEdGdjZ6aXorWE8xZS8zCmtTSFRnckc1N1BWb2FtM0xx"
                   "c2xBV00yellGNVROU0hEQ3VIYkRwRFFQdFFKZWswcG15UFc5dTRoYUdE"
                   "aXRHbm4KRUFFMHo0WT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=",
        # "runtime_id": "..."
    }

    # Build webapp with correct runtime_id
    @classmethod
    def build_webapp(cls, db):
        runtime_id = str(db.runtime1.id)
        new_webapp = dict(cls._webapp_input)
        new_webapp["runtime_id"] = runtime_id
        return new_webapp

    @staticmethod
    def build_output(db):
        webapp = json.loads(webapp_schema.dumps(db.webapp1).data)
        return webapp

    ################################################
    # Testing POST /capsules/{cId}/webapp
    ################################################
    # Response 201:
    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_create(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_absent") as publish_method1, \
             patch.object(NATS, "publish_webapp_present") as publish_method2:
            capsule_id = str(db.capsule1.id)

            # Remove existing webapp
            testapp.delete(
                api_version + '/capsules/' + capsule_id + '/webapp',
                status=204
            )
            publish_method1.assert_called_once

            # Create webapp
            new_webapp = self.build_webapp(db)

            res = testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                new_webapp,
                status=201
            ).json
            publish_method2.assert_called_once

            # tls crt & key are not displayed in res
            new_webapp.pop('tls_key')
            new_webapp.pop('tls_crt')
            assert dict_contains(res, new_webapp)

    # Response 400:
    def test_create_bad_capsule_id(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            new_webapp = self.build_webapp(db)
            res = testapp.post_json(
                api_version + '/capsules/' + bad_id + '/webapp',
                new_webapp,
                status=400
            ).json
            msg = f"'{bad_id}' is not a valid id."
            assert msg in res['error_description']

    def test_create_missing_runtime_id(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            capsule_id = str(db.capsule1.id)
            res = testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                self._webapp_input,
                status=400
            ).json
            msg = "'runtime_id' is a required property"
            assert msg in res['error_description']

    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_create_bad_runtime_id(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_absent"):

            capsule_id = str(db.capsule1.id)
            # Remove existing webapp
            testapp.delete(
                api_version + '/capsules/' + capsule_id + '/webapp',
                status=204
            )

            new_webapp = self.build_webapp(db)
            new_webapp['runtime_id'] = bad_id
            res = testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                new_webapp,
                status=400
            ).json
            msg = f"'{bad_id}' is not a valid id."
            assert msg in res['error_description']

    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_create_unexisting_runtime_id(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_absent"):

            capsule_id = str(db.capsule1.id)
            # Remove existing webapp
            testapp.delete(
                api_version + '/capsules/' + capsule_id + '/webapp',
                status=204
            )

            new_webapp = self.build_webapp(db)
            new_webapp['runtime_id'] = unexisting_id
            res = testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                new_webapp,
                status=400
            ).json
            msg = f"'{unexisting_id}' does not exist."
            assert msg in res['error_description']

    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_create_with_addon_runtime_id(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_absent"):

            capsule_id = str(db.capsule1.id)
            # Remove existing webapp
            testapp.delete(
                api_version + '/capsules/' + capsule_id + '/webapp',
                status=204
            )

            new_webapp = self.build_webapp(db)
            new_webapp['runtime_id'] = str(db.runtime2.id)
            res = testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                new_webapp,
                status=400
            ).json
            msg = "has not type 'webapp'"
            assert msg in res['error_description']

    def test_create_missing_fqdns(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            capsule_id = str(db.capsule1.id)
            # Build webapp with correct runtime_id but no fqdns
            new_webapp = self.build_webapp(db)
            new_webapp.pop("fqdns")

            testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                new_webapp,
                status=400
            )

    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_create_only_tls_key(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_absent") as publish_method1, \
             patch.object(NATS, "publish_webapp_present") as publish_method2:
            capsule_id = str(db.capsule1.id)

            # Remove existing webapp
            testapp.delete(
                api_version + '/capsules/' + capsule_id + '/webapp',
                status=204
            )
            publish_method1.assert_called_once

            # Create webapp
            new_webapp = self.build_webapp(db)
            new_webapp.pop('tls_crt')

            res = testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                new_webapp,
                status=400
            ).json
            publish_method2.assert_called_once
            msg = "Both tls_crt and tls_key are required together"
            assert msg in res['error_description']

    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_create_tls_key_not_b64(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_absent") as publish_method1, \
             patch.object(NATS, "publish_webapp_present") as publish_method2:
            capsule_id = str(db.capsule1.id)

            # Remove existing webapp
            testapp.delete(
                api_version + '/capsules/' + capsule_id + '/webapp',
                status=204
            )
            publish_method1.assert_called_once

            # Create webapp
            new_webapp = self.build_webapp(db)
            new_webapp['tls_crt'] = "totot"

            res = testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                new_webapp,
                status=400
            ).json
            publish_method2.assert_called_once
            msg = "'tls_crt' and 'tls_key' must be base64 encoded."
            assert msg in res['error_description']

    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_create_tls_key_invalid(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_absent") as publish_method1, \
             patch.object(NATS, "publish_webapp_present"):
            capsule_id = str(db.capsule1.id)

            # Remove existing webapp
            testapp.delete(
                api_version + '/capsules/' + capsule_id + '/webapp',
                status=204
            )
            publish_method1.assert_called_once

            # Create webapp
            new_webapp = self.build_webapp(db)
            new_webapp['tls_crt'] = "toto"

            testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                new_webapp,
                status=400
            )

    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_create_tls_crt_key_not_paired(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_absent") as publish_method1, \
             patch.object(NATS, "publish_webapp_present") as publish_method2:
            capsule_id = str(db.capsule1.id)

            # Remove existing webapp
            testapp.delete(
                api_version + '/capsules/' + capsule_id + '/webapp',
                status=204
            )
            publish_method1.assert_called_once

            # Create webapp
            new_webapp = self.build_webapp(db)
            new_webapp['tls_key'] = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1J"\
                                    "SUJWUUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVND"\
                                    "QVQ4d2dnRTdBZ0VBQWtFQTdDYktkdW55RmlqVm9V"\
                                    "R0gKWDRhS1Q5Y0Q1SWw5OERZSUFabm9TbGJHeFYy"\
                                    "WUlsVXhZZ1JvYjRGRThYYXV6SVlqZWNFM2J3Tmlj"\
                                    "TkRxOU5SUAoxUlJvU3dJREFRQUJBa0VBcm81aDNC"\
                                    "SkRrdU91UFp0TmNHdm5zdXB4Z3kycWZMUERxVU5W"\
                                    "dEJWK3FnV0FYNDhHCmlhUjA1YXlhY0JiNTJtb2ZO"\
                                    "b0lZU3RUZHk5WkpsZFh2MlIxSDJRSWhBUFlrUDZX"\
                                    "TW93Q3NYdWxiZlViTUl5cVQKSllEL1ZkUXU2SGo5"\
                                    "ZHNMVzNhMTNBaUVBOVp3Y2tFanRiVy9xWTJ5cG90"\
                                    "ZlJNYit3N1FsbVU3b3JGaWd0R1NrVApnTTBDSUZq"\
                                    "UUJZTVhkcTFFaE02UXEyaERPaUVmalBXNXE5OXV1"\
                                    "WVVHZDdhZnpzYkxBaUJ4N3EzdFhIY08rZ2h2CmdK"\
                                    "dWNWNkxLQWhNUGtmbXV3MEJ6Y2NXaDAwVWh6UUlo"\
                                    "QUkydnE0aFBFMVkrMFJGVkpxaEJnVGFrQ1Nsb1ly"\
                                    "SzUKcTdXS1BLYTJRZG4zCi0tLS0tRU5EIFBSSVZB"\
                                    "VEUgS0VZLS0tLS0K"

            res = testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                new_webapp,
                status=400
            ).json
            publish_method2.assert_called_once
            msg = "The certificate and the key are not associated"
            assert msg in res['error_description']

    # Response 401:
    def test_create_with_no_token(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        new_webapp = self.build_webapp(db)

        testapp.post_json(
            api_version + '/capsules/' + capsule_id + '/webapp',
            new_webapp,
            status=401
        )

    # Response 403:
    def test_create_bad_owner(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):
            capsule_id = str(db.capsule1.id)
            new_webapp = self.build_webapp(db)

            testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                new_webapp,
                status=403
            )

    # Response 409:
    def test_create_conflict(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):
            capsule_id = str(db.capsule1.id)
            new_webapp = self.build_webapp(db)

            res = testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                new_webapp,
                status=409
            ).json
            msg = "This capsule already has a webapp."
            assert msg in res["error_description"]
    ################################################

    ################################################
    # Testing GET /capsules/{cId}/webapp
    ################################################
    # Response 401:
    def test_get_with_no_token(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        testapp.get(
            api_version + "/capsules/" + capsule_id + "/webapp",
            status=401
        )

    # Response 403:
    def test_get_raise_bad_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            testapp.get(
                api_version + "/capsules/" + capsule_id + "/webapp",
                status=403
            )

    # Response 404:
    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_get_not_found(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_absent") as publish_method:

            # Remove existing webapp
            testapp.delete(
                api_version + '/capsules/' + capsule_id + '/webapp',
                status=204
            )
            publish_method.assert_called_once

            testapp.get(
                api_version + "/capsules/" + capsule_id + "/webapp",
                status=404
            )

    # Response 200:
    def test_get(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        webapp_output = self.build_output(db)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(
                api_version + "/capsules/" + capsule_id + "/webapp",
                status=200
            ).json
            assert dict_contains(res, webapp_output)
    ################################################

    ################################################
    # Testing PUT /capsules/{cId}/webapp
    ################################################
    # Response 200:
    def test_update(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_present") as publish_method:

            current_webapp = self.build_output(db)
            current_webapp.pop('id')
            current_webapp.pop('created_at')
            current_webapp.pop('updated_at')
            current_webapp["fqdns"] = [
                {
                    "alias": False,
                    "name": "domain.test.tld",
                }
            ]
            current_webapp["tls_redirect_https"] = False

            res = testapp.put_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                current_webapp,
                status=200
            ).json
            publish_method.assert_called_once
            assert dict_contains(res, current_webapp)

    def test_update_with_tls(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_present") as publish_method:

            current_webapp = self.build_output(db)
            current_webapp.pop('id')
            current_webapp.pop('created_at')
            current_webapp.pop('updated_at')
            current_webapp['tls_crt'] = self._webapp_input['tls_crt']
            current_webapp['tls_key'] = self._webapp_input['tls_key']

            testapp.put_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                current_webapp,
                status=200
            )
            publish_method.assert_called_once

    # Response 201:
    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_update_unexisting_webapp(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_absent") as publish_method1, \
             patch.object(NATS, "publish_webapp_present") as publish_method2:

            # Remove existing webapp
            testapp.delete(
                api_version + '/capsules/' + capsule_id + '/webapp',
                status=204
            )
            publish_method1.assert_called_once

            new_webapp = self.build_webapp(db)

            res = testapp.put_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                new_webapp,
                status=201
            ).json
            publish_method2.assert_called_once

            # tls crt & key are not displayed in res
            new_webapp.pop('tls_key')
            new_webapp.pop('tls_crt')
            assert dict_contains(res, new_webapp)

    # Response 400:
    def test_update_bad_request(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            testapp.put_json(
                api_version + "/capsules/" + bad_id + '/webapp',
                self._webapp_input,
                status=400
            )

    def test_update_bad_runtime_id(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_present"):

            current_webapp = self.build_output(db)
            current_webapp.pop('id')
            current_webapp.pop('created_at')
            current_webapp.pop('updated_at')
            current_webapp["runtime_id"] = bad_id

            res = testapp.put_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                current_webapp,
                status=400
            ).json
            msg = f"'{bad_id}' is not a valid id."
            assert msg in res['error_description']

    def test_update_unexisting_runtime_id(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_present"):

            current_webapp = self.build_output(db)
            current_webapp.pop('id')
            current_webapp.pop('created_at')
            current_webapp.pop('updated_at')
            current_webapp["runtime_id"] = unexisting_id

            res = testapp.put_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                current_webapp,
                status=400
            ).json
            msg = f"'{unexisting_id}' does not exist."
            assert msg in res['error_description']

    def test_update_with_addon_runtime_id(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_present"):

            current_webapp = self.build_output(db)
            current_webapp.pop('id')
            current_webapp.pop('created_at')
            current_webapp.pop('updated_at')
            current_webapp["runtime_id"] = str(db.runtime2.id)

            res = testapp.put_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                current_webapp,
                status=400
            ).json
            assert "Changing runtime familly" in res['error_description']

    def test_update_only_tls_crt(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_present"):

            current_webapp = self.build_output(db)
            current_webapp.pop('id')
            current_webapp.pop('created_at')
            current_webapp.pop('updated_at')
            current_webapp['tls_crt'] = self._webapp_input['tls_crt']

            res = testapp.put_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                current_webapp,
                status=400
            ).json
            msg = "Both tls_crt and tls_key are required together"
            assert msg in res['error_description']

    def test_update_tls_key_not_b64(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_present"):

            current_webapp = self.build_output(db)
            current_webapp.pop('id')
            current_webapp.pop('created_at')
            current_webapp.pop('updated_at')
            current_webapp['tls_crt'] = self._webapp_input['tls_crt']
            current_webapp['tls_key'] = "totot"

            res = testapp.put_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                current_webapp,
                status=400
            ).json
            msg = "'tls_crt' and 'tls_key' must be base64 encoded."
            assert msg in res['error_description']

    def test_update_tls_key_invalid(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_present"):

            current_webapp = self.build_output(db)
            current_webapp.pop('id')
            current_webapp.pop('created_at')
            current_webapp.pop('updated_at')
            current_webapp['tls_crt'] = self._webapp_input['tls_crt']
            current_webapp['tls_key'] = "toto"

            testapp.put_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                current_webapp,
                status=400
            )

    def test_update_tls_crt_key_not_paired(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_present"):

            webapp = self.build_output(db)
            webapp.pop('id')
            webapp.pop('created_at')
            webapp.pop('updated_at')
            webapp['tls_crt'] = self._webapp_input['tls_crt']
            webapp['tls_key'] = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1J"\
                                "SUJWUUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVND"\
                                "QVQ4d2dnRTdBZ0VBQWtFQTdDYktkdW55RmlqVm9V"\
                                "R0gKWDRhS1Q5Y0Q1SWw5OERZSUFabm9TbGJHeFYy"\
                                "WUlsVXhZZ1JvYjRGRThYYXV6SVlqZWNFM2J3Tmlj"\
                                "TkRxOU5SUAoxUlJvU3dJREFRQUJBa0VBcm81aDNC"\
                                "SkRrdU91UFp0TmNHdm5zdXB4Z3kycWZMUERxVU5W"\
                                "dEJWK3FnV0FYNDhHCmlhUjA1YXlhY0JiNTJtb2ZO"\
                                "b0lZU3RUZHk5WkpsZFh2MlIxSDJRSWhBUFlrUDZX"\
                                "TW93Q3NYdWxiZlViTUl5cVQKSllEL1ZkUXU2SGo5"\
                                "ZHNMVzNhMTNBaUVBOVp3Y2tFanRiVy9xWTJ5cG90"\
                                "ZlJNYit3N1FsbVU3b3JGaWd0R1NrVApnTTBDSUZq"\
                                "UUJZTVhkcTFFaE02UXEyaERPaUVmalBXNXE5OXV1"\
                                "WVVHZDdhZnpzYkxBaUJ4N3EzdFhIY08rZ2h2CmdK"\
                                "dWNWNkxLQWhNUGtmbXV3MEJ6Y2NXaDAwVWh6UUlo"\
                                "QUkydnE0aFBFMVkrMFJGVkpxaEJnVGFrQ1Nsb1ly"\
                                "SzUKcTdXS1BLYTJRZG4zCi0tLS0tRU5EIFBSSVZB"\
                                "VEUgS0VZLS0tLS0K"

            res = testapp.put_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                webapp,
                status=400
            ).json
            msg = "The certificate and the key are not associated"
            assert msg in res['error_description']

    # Response 401:
    def test_update_unauthenticated(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        new_webapp = self.build_webapp(db)
        testapp.put_json(
            api_version + "/capsules/" + capsule_id + '/webapp',
            new_webapp,
            status=401
        )

    # Response 403:
    def test_update_bad_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            new_webapp = self.build_webapp(db)

            testapp.put_json(
                api_version + "/capsules/" + capsule_id + "/webapp",
                new_webapp,
                status=403
            )

    ################################################

    ################################################
    # Testing DELETE /capsules/{cId}/webapp
    ################################################
    # Response 204:
    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_delete(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_absent") as publish_method:

            # Delete webapp
            testapp.delete(
                api_version + "/capsules/" + capsule_id + "/webapp",
                status=204
            )
            publish_method.assert_called_once

            # Check webapp is not present anymore
            testapp.get(
                api_version + "/capsules/" + capsule_id + "/webapp",
                status=404
            )

    # Response 401:
    def test_delete_unauthorized(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        testapp.delete(
            api_version + "/capsules/" + capsule_id + "/webapp",
            status=401
        )

    # Response 403:
    def test_delete_bad_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            testapp.delete(
                api_version + "/capsules/" + capsule_id + "/webapp",
                status=403
            )

    # Response 404:
    def test_delete_not_found_capsule_id(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            testapp.delete(
                api_version + "/capsules/" + unexisting_id + "/webapp",
                status=404
            )

    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_delete_no_webapp(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch("api.capsules.owners.check_owners_on_keycloak"), \
             patch.object(NATS, "publish_webapp_absent") as publish_method:

            # Delete webapp
            testapp.delete(
                api_version + "/capsules/" + capsule_id + "/webapp",
                status=204
            )
            publish_method.assert_called_once

            # Try to delete an unexisting webapp
            res = testapp.delete(
                api_version + "/capsules/" + capsule_id + "/webapp",
                status=404
            ).json
            msg = "This capsule does not have webapp."
            assert msg in res["error_description"]
    ################################################
