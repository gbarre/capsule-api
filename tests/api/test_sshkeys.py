from tests.utils import api_version, bad_id, dict_contains, unexisting_id
from app import oidc
from unittest.mock import patch
from werkzeug.exceptions import Forbidden
import pytest
from nats import NATS


class TestSshKeys:

    _sshkey_input = {
        "public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDVbtGe1p6vAjwizq"
                      "EiO8EY5K3jyB7NoBT+gDREp6TcimUMJzsWryJampX7IqDpkC7I2/Y7"
                      "oiUudVR97Q6H//IckCJetaD/yONkqzRCxCoQz+J0JWlMZsS/MmIy6B"
                      "HDrLYB6KBZ4zk6exxbxcanJnz2fHahom8GE57l9khYgm3WLGi+v3of"
                      "b6ZsT6BrR8eXRpb6wJ6HcghGRwWg7+M6IMqZdprvzGomc7UO3fPmQX"
                      "f3KF9ZlelNCBsczD4qrYshiScVqmWmo2jePTDESWaaP3jlqz7Ekvfx"
                      "ukAuTm2spohtmVs+iwxOTvEwP3o7ucfp/o7QRYPqL/OPXAN8pjzf8z"
                      "Z2 toto@input"
    }

    @staticmethod
    def build_output(db):
        ret = [
            {
                "public_key": db.sshkey1.public_key,
            },
            {
                "public_key": db.sshkey2.public_key,
            },
        ]

        return ret

    #################################
    # Testing GET /sshkeys
    #################################
    # Response 200:
    def test_get(self, testapp, db):
        sshkeys_output = self.build_output(db)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(
                api_version + "/sshkeys",
                status=200
            ).json
            assert dict_contains(res[0], sshkeys_output[0])

    def test_get_all(self, testapp, db):
        sshkeys_output = self.build_output(db)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):

            res = testapp.get(
                api_version + "/sshkeys",
                status=200
            ).json
            assert dict_contains(res, sshkeys_output)

    # Response 401:
    def test_get_with_no_token(self, testapp, db):
        testapp.get(
            api_version + "/sshkeys",
            status=401
        )

    # Response 404:
    def test_get_not_found(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            testapp.get(
                api_version + "/sshkeys",
                status=404
            )
    #################################

    #################################
    # Testing POST /sshkeys
    #################################
    # Response 201:
    def test_create(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_present") as publish_method:

            res = testapp.post_json(
                api_version + "/sshkeys",
                self._sshkey_input,
                status=201
            ).json
            publish_method.assert_called_once()
            assert dict_contains(res, self._sshkey_input)

    # Response 400:
    def test_create_bad_json(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            input_data = {"foo": "bar"}
            res = testapp.post_json(
                api_version + "/sshkeys",
                input_data,
                status=400
            ).json
            assert "'public_key' is required" in res['error_description']

    def test_create_bad_sshkey(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            input_data = dict()
            input_data['public_key'] = self._sshkey_input['public_key'][8:]
            res = testapp.post_json(
                api_version + "/sshkeys",
                input_data,
                status=400
            ).json
            assert "not a valid ssh public" in res['error_description']

    # Response 401:
    def test_create_with_no_token(self, testapp, db):
        testapp.post_json(
            api_version + "/sshkeys", self._sshkey_input, status=401)
    #################################

    #################################
    # Testing DELETE /sshkeys/kId
    #################################
    # Response 204:
    # FIXME: how to remove the header "Content-Type" for DELETE request only?
    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_delete_sshkey(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):

            # Get sshkey id
            sshkey = db.sshkey1
            sshkey_id = str(sshkey.id)

            # Delete this sshkey
            testapp.delete(
                api_version + "/sshkeys/" + sshkey_id,
                status=204
            )

            # Ensure this sshkey is not present anymore
            res = testapp.get(
                api_version + "/sshkeys",
                status=200
            )
            assert sshkey.public_key not in res

    # Response 400:
    def test_delete_bad_sshkey(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.fake_user):

            testapp.delete(
                api_version + '/sshkeys/' + bad_id,
                status=400
            )

    # Response 401:
    def test_delete_unauthenticated(self, testapp, db):
        sshkey_id = str(db.sshkey1.id)

        # Delete this sshkey
        testapp.delete(
            api_version + "/sshkeys/" + sshkey_id, status=401)

    # Response 403:
    def test_delete_insufficient_rights(self, testapp, db):
        sshkey_id = str(db.sshkey1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", side_effect=Forbidden):

            # Delete this sshkey
            testapp.delete(
                api_version + "/sshkeys/" + sshkey_id,
                status=403
            )

    def test_delete_wrong_user(self, testapp, db):
        sshkey_id = str(db.sshkey3.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            # Delete this sshkey
            testapp.delete(
                api_version + "/sshkeys/" + sshkey_id,
                status=403
            )

    # Response 404:
    def test_delete_unexisting_sshkey(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.fake_user):

            res = testapp.delete(
                api_version + '/sshkeys/' + unexisting_id,
                status=404
            ).json
            msg = f"The requested sshkey '{unexisting_id}' has not been found."
            assert msg in res['error_description']
    #################################
