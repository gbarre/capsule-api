import pytest
from tests.utils import api_version, bad_id, dict_contains, unexisting_id
from app import oidc
from unittest.mock import patch
from models import fqdn_schema
import json

from nats import NATS


class TestCapsuleTls:

    _disable_tls_input = {
        "enable_https": False
    }

    _tls_input = {
        "force_redirect_https": True,
        "enable_https": True,
        "certificate": "acme",
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

    ################################################
    # Testing PATCH /capsules/{cId}/tls
    ################################################
    # Response 400:
    def test_patch_bad_request_wrong_capsule_id(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):
            res = testapp.patch_json(
                api_version + "/capsules/" + bad_id + "/tls",
                self._tls_input,
                status=400
            ).json
            msg = f"'{bad_id}' is not a valid id."
            assert msg in res['error_description']

    def test_patch_only_crt(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):

            input = dict(self._tls_input)
            input.pop('key')
            res = testapp.patch_json(
                api_version + "/capsules/" + capsule_id + "/tls",
                input,
                status=400
            ).json
            msg = "Both crt and key are required together"
            assert msg in res['error_description']

    def test_patch_only_key(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):

            input = dict(self._tls_input)
            input.pop('crt')
            res = testapp.patch_json(
                api_version + "/capsules/" + capsule_id + "/tls",
                input,
                status=400
            ).json
            msg = "Both crt and key are required together"
            assert msg in res['error_description']

    def test_patch_key_not_b64(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):

            input = dict(self._tls_input)
            input['key'] = "This is not a base64 string"
            res = testapp.patch_json(
                api_version + "/capsules/" + capsule_id + "/tls",
                input,
                status=400
            ).json
            msg = "'crt' and 'key' must be base64 encoded."
            assert msg in res['error_description']

    def test_patch_key_crt_not_associated(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):

            input = dict(self._tls_input)
            input['key'] = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUNkd0l"\
                           "CQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQW1Fd2dnSmRBZ0"\
                           "VBQW9HQkFMbzBUMGdrcUNNdUUzYXUKSzN1Sml5WE9wa1ZHN"\
                           "GRkVkVmTWpWenN3MFAvNWtGdmRwdFB6SHp4MUg5ZGVqbjZt"\
                           "N056NDV4cW13NDNMTEFsMApMSis5OVMxUXhXdElpWldHaFB"\
                           "EUWR6aXlMd29XMUdtMWg4STNXYlBDQVZtVGtGdngzTi9oOT"\
                           "dDNnY0MHk5S2diCmpFRU9uc2pZOUNNL2pJZ1RncytDemwxc"\
                           "nkyTnRBZ01CQUFFQ2dZRUFsYU5TRDF6K0RmK0tQcmJyVk1V"\
                           "TklOMzQKT3ZZaXFrVEFQdytvbTNXNGorMUQrTCtnd1BYQnB"\
                           "YbE9sR3Axd3d4c2o0d3JWUHl0YkxiWTllUDV0SW9ZaStubA"\
                           "p5S3E0WkxjakRCWXRYZWpscVA1bzFTaWdHci9PK0FCc1dvT"\
                           "GM1ZUFseVRkSm5vZFdLQ3JKZmRSaEZYSjdEMkEyCjVFQTlP"\
                           "ZEppVlBmV3NKbGlzTUVDUVFEbFN3Z1FzOHdpTkI5WjFKYnF"\
                           "NVVVhN0FoUDFsaDNvMnNQdDZaVVRKdWYKV3F6VGw1L1FNc1"\
                           "pOSk9QMHVvb1dUQlNobmJvMDNUN1FxVXJZalhxRnZ3ZHhBa"\
                           "0VBeitSNW42VTRsVlBjSlc0RApueDFabzZ2NU1oRGhma3c0"\
                           "QytuRHFTZFU5QlN6TlhzS0JoOGFGR0pHZW1aY2pFazU2enl"\
                           "XZm1nWWZGRThlMzZ5CnRZQzF2UUpCQUsxWlkzaVZKZkI1N1"\
                           "hYUmxtTHA2dS9tb0lZVGJBRFBLS0xTV2txRFBHaG1laURpR"\
                           "WUycVpXZHYKUzNQN0QyaTZEaUw5aHdodWVBM3kzMllHMkNt"\
                           "RGVkRUNRR0JXZms0TzRKUENrc2Y5blV3RTY5OCsrSEhOQk5"\
                           "IawpQQ3k1SFdTcngyQjhuemR2Vnd2VEtlQzhVZkN5c3J5SH"\
                           "lvRktTR3MzamZFK0xBc0dnWVkrcVBrQ1FDcndjbmJ2CnJWM"\
                           "0h3eXNHamhkNzZtdVZHNkEyZFplV2hNNnRtQUFEb0o4bWJK"\
                           "VUkzMGlpNWhseUxWb1hPMElGUFU0c2psNkcKUjBOazUyOTh"\
                           "wTE1jNmhnPQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg=="

            res = testapp.patch_json(
                api_version + "/capsules/" + capsule_id + "/tls",
                input,
                status=400
            ).json
            msg = "The certificate and the key are not associated"
            assert msg in res['error_description']

    def test_patch_acme_failed(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        fqdn_id = str(db.fqdn1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch("api.capsules.check_owners_on_keycloak"), \
             patch.object(NATS, "publish_webapp_present"):

            # Update capsule FQDN (set not acme valid)
            current_fqdn = json.loads(fqdn_schema.dumps(db.fqdn1))
            current_fqdn['name'] = "new.fqdn.com"
            current_fqdn.pop('id')
            testapp.put_json(
                f'{api_version}/capsules/{capsule_id}/fqdns/{fqdn_id}',
                current_fqdn,
                status=200
            )

            # Try set acme certificate for this capsule
            new_input = dict(self._tls_input)
            new_input.pop('crt')
            new_input.pop('key')
            res = testapp.patch_json(
                api_version + "/capsules/" + capsule_id + "/tls",
                self._tls_input,
                status=400
            ).json
            msg = 'does not match any of the following domains'
            assert msg in res["error_description"]

    # Response 401:
    def test_patch_unauthorized(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        testapp.patch_json(
            api_version + "/capsules/" + capsule_id + "/tls",
            self._tls_input,
            status=401
        )

    # Response 403:
    def test_patch_forbidden_no_delegate(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):
            testapp.patch_json(
                api_version + "/capsules/" + capsule_id + "/tls",
                self._tls_input,
                status=403
            )

    def test_patch_forbidden_not_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            # Add tls delegation for test
            delegate = {"tls": True}
            testapp.patch_json(
                api_version + "/capsules/" + capsule_id + "/delegate",
                delegate,
                status=200
            )

            testapp.patch_json(
                api_version + "/capsules/" + capsule_id + "/tls",
                self._tls_input,
                status=403
            )

    # Response 404:
    def test_patch_not_found_capsule_id(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):

            testapp.patch_json(
                api_version + "/capsules/" + unexisting_id + "/tls",
                self._tls_input,
                status=404
            )

    # Response 200:
    def test_patch(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch.object(NATS, "publish_webapp_present") as publish_method:

            res = testapp.patch_json(
                api_version + "/capsules/" + capsule_id + "/tls",
                self._tls_input,
                status=200
            ).json
            publish_method.assert_called_once()
            # crt and key are not displayed in result...
            input = dict(self._tls_input)
            input.pop('crt')
            input.pop('key')
            assert dict_contains(res, input)

    def test_patch_with_delegate(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_present") as publish_method:

            # Add tls delegation for test
            delegate = {"tls": True}
            testapp.patch_json(
                api_version + "/capsules/" + capsule_id + "/delegate",
                delegate,
                status=200
            )

            testapp.patch_json(
                api_version + "/capsules/" + capsule_id + "/tls",
                self._tls_input,
                status=200
            )
            publish_method.assert_called_once()

    def test_patch_http(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch.object(NATS, "publish_webapp_present") as publish_method:

            input = dict(self._tls_input)
            input['force_redirect_https'] = False
            input['enable_https'] = False
            res = testapp.patch_json(
                api_version + "/capsules/" + capsule_id + "/tls",
                input,
                status=200
            ).json
            publish_method.assert_called_once()
            assert res['force_redirect_https'] is \
                input['force_redirect_https']
            assert res['enable_https'] is input['enable_https']
    ################################################

    ################################################
    # Testing GET /capsules/{cId}/tls
    ################################################
    # Response 200:
    def test_get_certificate(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        # Insert cerrtificate
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch.object(NATS, "publish_webapp_present"):

            testapp.patch_json(
                api_version + "/capsules/" + capsule_id + "/tls",
                self._tls_input,
                status=200
            )

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            testapp.get(
                api_version + "/capsules/" + capsule_id + "/tls",
                status=200
            )

    # Response 400:
    def test_get_bad_request_wrong_capsule_id(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):
            res = testapp.get(
                api_version + "/capsules/" + bad_id + "/tls",
                status=400
            ).json
            msg = f"'{bad_id}' is not a valid id."
            assert msg in res['error_description']

    # Response 401:
    def test_get_unauthorized(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        testapp.get(
            api_version + "/capsules/" + capsule_id + "/tls",
            status=401
        )

    # Response 403:
    def test_get_forbidden_not_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        # Insert cerrtificate
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch.object(NATS, "publish_webapp_present"):

            testapp.patch_json(
                api_version + "/capsules/" + capsule_id + "/tls",
                self._tls_input,
                status=200
            )

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            testapp.get(
                api_version + "/capsules/" + capsule_id + "/tls",
                status=403
            )

    # Response 404:
    def test_get_crt_not_found(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(
                api_version + "/capsules/" + capsule_id + "/tls",
                status=404
            ).json

            msg = f"capsule '{capsule_id}' does not have certificate."
            assert msg in res['error_description']

    def test_get_not_found_capsule_id(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):

            testapp.get(
                api_version + "/capsules/" + unexisting_id + "/tls",
                status=404
            )
    ################################################

    ################################################
    # Testing DELETE /capsules/{cId}/tls
    ################################################
    # Response 204:
    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_delete(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch.object(NATS, "publish_webapp_present") as publish_method:

            # Disable tls before remove certificate
            testapp.patch_json(
                f'{api_version}/capsules/{capsule_id}/tls',
                self._disable_tls_input,
                status=200
            )

            # Delete certificate
            testapp.delete(
                f'{api_version}/capsules/{capsule_id}/tls',
                status=204
            )
            publish_method.call_count = 2
            publish_method.assert_called()

    # Response 400:
    def test_delete_bad_id(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):

            testapp.delete(
                f'{api_version}/capsules/{bad_id}/tls',
                status=400
            )

    # Response 401:
    def test_delete_unauthorized(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        testapp.delete(
            f'{api_version}/capsules/{capsule_id}/tls',
            status=401
        )

    # Response 403:
    def test_delete_without_delegation(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.delete(
                f'{api_version}/capsules/{capsule_id}/tls',
                status=403
            ).json
            msg = 'Delegation is not activate for users.'
            assert msg in res['error_description']

    def test_delete_bad_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            # Add tls delegation for test
            delegate = {"tls": True}
            testapp.patch_json(
                api_version + "/capsules/" + capsule_id + "/delegate",
                delegate,
                status=200
            )

            testapp.delete(
                f'{api_version}/capsules/{capsule_id}/tls',
                status=403
            )

    # Response 404:
    def test_delete_not_found(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):

            testapp.delete(
                f'{api_version}/capsules/{unexisting_id}/tls',
                status=404
            )

    # Response 409:
    def test_delete_conflict(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):

            # Delete certificate
            res = testapp.delete(
                f'{api_version}/capsules/{capsule_id}/tls',
                status=409
            ).json

            msg = 'Please, disable HTTPS for this capsule before ' \
                  'trying to remove the certificate.'
            assert msg in res['error_description']

    ################################################
