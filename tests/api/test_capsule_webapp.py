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
        "opts": [
            {
                "field_name": "worker",
                "tag": "PHP",
                "value": "42"
            },
        ],
    }

    _fqdns_input = [
        {
            "name": "main.example.com",
            "alias": False
        },
        {
            "name": "sub.secondary.my-example.com",
            "alias": True
        },
    ]

    _tls_input = {
        "redirect_https": False,
        "crt": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURhekNDQWxPZ0F3S"
               "UJBZ0lVTWVYdFZ2clpGUnNvQ1RqcUVoekZRSTVHbmZvd0RRWUpLb1pJaH"
               "ZjTkFRRUwKQlFBd1JURUxNQWtHQTFVRUJoTUNRVlV4RXpBUkJnTlZCQWd"
               "NQ2xOdmJXVXRVM1JoZEdVeElUQWZCZ05WQkFvTQpHRWx1ZEdWeWJtVjBJ"
               "RmRwWkdkcGRITWdVSFI1SUV4MFpEQWVGdzB5TURBMk16QXhOREEwTlROY"
               "UZ3MHlNREEzCk16QXhOREEwTlROYU1FVXhDekFKQmdOVkJBWVRBa0ZWTV"
               "JNd0VRWURWUVFJREFwVGIyMWxMVk4wWVhSbE1TRXcKSHdZRFZRUUtEQmh"
               "KYm5SbGNtNWxkQ0JYYVdSbmFYUnpJRkIwZVNCTWRHUXdnZ0VpTUEwR0NT"
               "cUdTSWIzRFFFQgpBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRRFYzd2V2cTMyc"
               "XErTWVDYmYxeWpBNnl5aUdZV3hQeW8xMEVYbW9PYWJjCnpHV2QzUEhvWG"
               "FpOFlud1c4Z2twNHQ3bTErL2NWZWROZWhCUk9qRVNKbDZFKzNhNE1WSmp"
               "0bTQzSWVFQzhkNUcKU1p0K0JQVzAwZldSYStnZTVZeW56Q1pxTGY3K1pM"
               "RjFLaUl1c3ZyUlJWdWZvN0JDQXJwVDhvZ1NlMzAva0tSSgpRZzBLR3U0M"
               "WlVb3JWVzQyRWRBdDNQZ3RKNFNRSTlKckdZSUJsaUxNcW1PUmlER2NmNH"
               "duNVo1aXJPakF5QWtOClVPZlFqc20vWDBpR00zZWJaTXZIeFV5U3ovd0t"
               "oMXVnaFpaU1JPVHFSem1xek9QSkRmdE1QMmViZDhZb1l3RCsKTmZIb3ll"
               "Y3J4cmxvRE5ER2UreklPL0w2NmZTVVhXM2czblVlcEc5M3JIR0ZBZ01CQ"
               "UFHalV6QlJNQjBHQTFVZApEZ1FXQkJSN1pRQ0NKc1hOYTVjNUEyTE1EYk"
               "tlK1FNWEVqQWZCZ05WSFNNRUdEQVdnQlI3WlFDQ0pzWE5hNWM1CkEyTE1"
               "EYktlK1FNWEVqQVBCZ05WSFJNQkFmOEVCVEFEQVFIL01BMEdDU3FHU0li"
               "M0RRRUJDd1VBQTRJQkFRQzkKVmhtNi9ick1LNjM0ZHZRZFZHMW5VWkNPS"
               "mEzbHl5RzArV1JKSWJhbGhHSFBncElqK3pzWXFIeXlnWXRCTkJSbwovaV"
               "ZmYjkwenRyUzR3RWhLWXp5YkhDRVk5S21WakpIS2xwa0JjeFI0OCszazZ"
               "Pb2kxYzQ2RXo0bWdhZGhDQ0dpClJCd01VZ0tFMDdjNlpZWUY4U2RBWTFm"
               "UXRKL3o2SytTTXovZjREMzJKMmxiaEc1d2dONzVuQVV5S3dLSStCMHUKZ"
               "mxVWGM2S1ZxUzVWazFobUdwYm00a3BKcWhvQWdLMUJNdG94VGwzSDVzdn"
               "NydWFNOWVJUExnMWJIRnE2YncwZgo2RGs1NlJGdTFIcmVsRzJtVTFGSVN"
               "jQXpEQi95eTlFQ2dqWHRuZituNXQraWpyem9HbkZjMDZOVkQrTkdyM0xn"
               "CnNOM0R6amhjM0s4ckdHZCtXZVhjCi0tLS0tRU5EIENFUlRJRklDQVRFL"
               "S0tLS0K",
        "key": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2Z0lCQURBTkJna"
               "3Foa2lHOXcwQkFRRUZBQVNDQktnd2dnU2tBZ0VBQW9JQkFRRFYzd2V2cT"
               "MycXErTWUKQ2JmMXlqQTZ5eWlHWVd4UHlvMTBFWG1vT2FiY3pHV2QzUEh"
               "vWGFpOFlud1c4Z2twNHQ3bTErL2NWZWROZWhCUgpPakVTSmw2RSszYTRN"
               "VkpqdG00M0llRUM4ZDVHU1p0K0JQVzAwZldSYStnZTVZeW56Q1pxTGY3K"
               "1pMRjFLaUl1CnN2clJSVnVmbzdCQ0FycFQ4b2dTZTMwL2tLUkpRZzBLR3"
               "U0MWlVb3JWVzQyRWRBdDNQZ3RKNFNRSTlKckdZSUIKbGlMTXFtT1JpREd"
               "jZjR3bjVaNWlyT2pBeUFrTlVPZlFqc20vWDBpR00zZWJaTXZIeFV5U3ov"
               "d0toMXVnaFpaUwpST1RxUnptcXpPUEpEZnRNUDJlYmQ4WW9Zd0QrTmZIb"
               "3llY3J4cmxvRE5ER2UreklPL0w2NmZTVVhXM2czblVlCnBHOTNySEdGQW"
               "dNQkFBRUNnZ0VCQUtoVXVIbjlvaFU0NExOOXRyclAvcEhuNE9lVHVtbzY"
               "1SWJjVWtLanpiK3YKYUxPTmVTRUl4b3d2ZjdlWG5MckpBK1B4UmFySU9o"
               "dHkzWER4T2pvczFPd1o5K0VWZ09GV2J2MFp2ejVRSEVCNgpJdFpYRlFUU"
               "zFGTTIrU1dJU3VLdS9mVklhcERUdEJDaHJ2SE9rVGN4UGVJeU5jSmUzMF"
               "MvZVhZQ21CdjF2amloClFVNDkxajNnMFd4TlVuMWlrR2Q3QXdQU1drVjk"
               "wd3kzSVFvWTFLdkdEUFJBMDE2RkgzNllta0xFMVgyMVptS3gKOVNHUFhC"
               "KzdhbjRKelVXZW1GdlpFYVNwWUVnaUNxSVVBSXI5UVVITU0xR1EwaGJFO"
               "FRTcjlNdElMV2xuNVpNYwpGK1M4UituZzJpVWxtOEpteFRra3ZQSkFtaz"
               "Q2RGViNE5ldGhUV1ExSDBFQ2dZRUE5akFqOXBCOUJUa2R5dUM2CmQrc1U"
               "2b3NDS1Vmdkd3Z2JjZ1h5dmJCWkg2NFoxK01lVVVrU28yTmJuZDlvaVIy"
               "dTYxZ2NCc1RSQ0x1TllFMGEKNjJYT0xZRGJMZEhDeFYyNi9acytDRUo0b"
               "1FGRTRKMTF5Z2lULzU5QUcvcDhTd1JxWGVOYVNqSHhPbzB2dnlEZQo1bn"
               "RqRFUzTFZ6N3k0Z3V0YXZ2YTcrTTMrYjBDZ1lFQTNtVXBGTCsrVXdrU3R"
               "hYzBoQU9pc0lZZVFsR3ZTZ1VjCnFsTkdhak1hbEYzUElWdWpBbFZvcmVW"
               "T1gzdml3b3h3N0ZMSmJUYVIrR1doaWRnWjNXU01oTzUzU1kzVTVzSjgKU"
               "2FaZlFGRVJIOWhGbVlBd0xia0NIek82ZWE3bTlzd080WXgxTGF6dkV4Yk"
               "hHN1kzZzR2UlVEVGI3ZWlKWjhSSgpnS3hza1Y2ZnYya0NnWUFCWWVQUnp"
               "wM2xHWjBCTnFIVmFveURoS1JPZHdqd3JlcjVpTzhFQWFsK2RBdlJHb1Zo"
               "CkQzZjdVdU9BejNCVzFNUFdybmY1MGNFYXUzTGZ4NDhQSTFNMURqUXMzY"
               "kNxU3d4eHdCMXBEblorOFBMaUVBQkoKVWlNQ25ISlB0ZWhjdzNtVmJXRm"
               "thVU5oZ01sejJVdG5IK28rZU9GYmJBOFJGZCt6YWhhZ29qWCtRUUtCZ0Y"
               "4QwpYS0NPb2VLYmQ3Qy9OQUpLQTFEaW16Njk0dUwrZUJhVDZQc3B4ZXNv"
               "Z0hyQnlVd1A3TjZObmdQUXl6bE9BbGdUCnJoWElRR2djRXZ6dW8yNGZyS"
               "0NGdDlSbWtWUGNObmpJYU56elJSdVRxM2crZVZhdk9TYlhWSXp6bVp4Sj"
               "VQbWEKcGR6VGluZGZQY1NxL2VCbTlROE01Z0FuWGJ4RThSblZqN1F5OXB"
               "BeEFvR0JBUE1HbSsvTUIwUVBWcFoyQ25hTgpLc3lkcHArUEhzWHM2RkNo"
               "WE9FbHczM0l1aU1ueWZ0SWp4N0xycTloc1BHeGc2M0RtcXE3VzZvdS94N"
               "ktSTnFqCkZnL2xKblV2eTNBUEJMb3QrUy9XeUgyM0R4WlFNZ09DQlhZa1"
               "Vxb2xYU0F1QnV3NGhXVEFqRGUyMkx5eElUZlgKcHU2bkE3SUZSaU5USzg"
               "4OEs1T0dWdHp1Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K",
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
        webapp = json.loads(webapp_schema.dumps(db.webapp1))
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
            publish_method1.assert_called_once()

            # Create webapp
            new_webapp = self.build_webapp(db)

            res = testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                new_webapp,
                status=201
            ).json
            publish_method2.assert_called_once()

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

    # Response 401:
    def test_create_with_no_token(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        new_webapp = self.build_webapp(db)

        testapp.post_json(
            api_version + '/capsules/' + capsule_id + '/webapp',
            new_webapp,
            status=401
        )

    # Response 402:
    def test_create_size_too_large(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch.object(NATS, "publish_webapp_absent"):
            capsule_id = str(db.capsule1.id)
            new_webapp = self.build_webapp(db)

            # Remove existing webapp
            testapp.delete(
                api_version + '/capsules/' + capsule_id + '/webapp',
                status=204
            )

            new_webapp['volume_size'] = 5000

            res = testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                new_webapp,
                status=402
            ).json
            assert 'Bitcoins' in res['error_description']

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

    def test_create_not_part_manager(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_absent"):
            capsule_id = str(db.capsule1.id)
            new_webapp = self.build_webapp(db)

            # Remove existing webapp
            testapp.delete(
                api_version + '/capsules/' + capsule_id + '/webapp',
                status=204
            )

            new_webapp['volume_size'] = 5

            res = testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                new_webapp,
                status=403
            ).json
            msg = "You cannot set webapp volume size."
            assert msg in res['error_description']

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
            publish_method.assert_called_once()

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
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch.object(NATS, "publish_webapp_present") as publish_method:

            current_webapp = self.build_output(db)
            current_webapp.pop('id')
            current_webapp.pop('created_at')
            current_webapp.pop('updated_at')
            current_webapp["env"] = {
                "HTTP_PROXY": "http://proxy.example.com:3128/",
                "HTTPS_PROXY": "http://proxy.example.com:3128/",
            }
            current_webapp["runtime_id"] = str(db.runtime4.id)
            current_webapp.pop('opts')

            res = testapp.put_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                current_webapp,
                status=200
            ).json
            publish_method.assert_called_once()
            assert dict_contains(res, current_webapp)

    def test_update_without_size(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_present") as publish_method:

            current_webapp = self.build_output(db)
            current_webapp.pop('id')
            current_webapp.pop('created_at')
            current_webapp.pop('updated_at')
            current_webapp.pop('volume_size')
            current_webapp["env"] = {
                "HTTP_PROXY": "http://proxy.example.com:3128/",
                "HTTPS_PROXY": "http://proxy.example.com:3128/",
            }
            current_webapp["runtime_id"] = str(db.runtime4.id)
            current_webapp.pop('opts')

            res = testapp.put_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                current_webapp,
                status=200
            ).json
            publish_method.assert_called_once()
            assert dict_contains(res, current_webapp)

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
            publish_method1.assert_called_once()

            new_webapp = self.build_webapp(db)

            res = testapp.put_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                new_webapp,
                status=201
            ).json
            publish_method2.assert_called_once()

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

    # Response 401:
    def test_update_unauthenticated(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        new_webapp = self.build_webapp(db)
        testapp.put_json(
            api_version + "/capsules/" + capsule_id + '/webapp',
            new_webapp,
            status=401
        )

    # Response 402:
    def test_update_size_too_large(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):
            capsule_id = str(db.capsule1.id)

            current_webapp = self.build_output(db)
            current_webapp.pop('id')
            current_webapp.pop('created_at')
            current_webapp.pop('updated_at')
            current_webapp['volume_size'] = 5000
            current_webapp["env"] = {
                "HTTP_PROXY": "http://proxy.example.com:3128/",
                "HTTPS_PROXY": "http://proxy.example.com:3128/",
            }
            current_webapp["runtime_id"] = str(db.runtime4.id)
            current_webapp.pop('opts')

            res = testapp.put_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                current_webapp,
                status=402
            ).json
            assert 'Bitcoins' in res['error_description']

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

    def test_update_not_parts_manager(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            current_webapp = self.build_output(db)
            current_webapp.pop('id')
            current_webapp.pop('created_at')
            current_webapp.pop('updated_at')
            current_webapp["env"] = {
                "HTTP_PROXY": "http://proxy.example.com:3128/",
                "HTTPS_PROXY": "http://proxy.example.com:3128/",
            }
            current_webapp["runtime_id"] = str(db.runtime4.id)
            current_webapp.pop('opts')

            res = testapp.put_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                current_webapp,
                status=403
            ).json
            msg = "You cannot set webapp volume size."
            assert msg in res['error_description']
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
            publish_method.assert_called_once()

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
            publish_method.assert_called_once()

            # Try to delete an unexisting webapp
            res = testapp.delete(
                api_version + "/capsules/" + capsule_id + "/webapp",
                status=404
            ).json
            msg = "This capsule does not have webapp."
            assert msg in res["error_description"]
    ################################################
