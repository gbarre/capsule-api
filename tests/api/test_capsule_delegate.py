from tests.utils import api_version, bad_id, unexisting_id
from app import oidc
from unittest.mock import patch


class TestCapsuleDelegate:

    _input = {
        "fqdns": True,
        "tls": True,
    }

    ################################################
    # Testing PATCH /capsules/{cId}/delegate
    ################################################
    # Response 400:
    def test_patch_bad_request_wrong_capsule_id(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):
            testapp.patch_json(
                api_version + "/capsules/" + bad_id + "/delegate",
                self._input,
                status=400
            )

    # Response 401:
    def test_patch_unauthorized(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        testapp.patch_json(
            api_version + "/capsules/" + capsule_id + "/delegate",
            self._input,
            status=401
        )

    # Response 404:
    def test_patch_not_found_capsule_id(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):

            testapp.patch_json(
                api_version + "/capsules/" + unexisting_id + "/delegate",
                self._input,
                status=404
            )

    # Response 200:
    def test_patch(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):

            res = testapp.patch_json(
                api_version + "/capsules/" + capsule_id + "/delegate",
                self._input,
                status=200
            ).json
            assert res['delegate_fqdns'] is self._input['fqdns']
            assert res['delegate_tls'] is self._input['tls']
    ################################################
