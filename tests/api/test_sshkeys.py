from app import oidc
from tests.utils import *
from unittest.mock import patch
import tests.foodata as foodata
from werkzeug.exceptions import Forbidden
from models import RoleEnum, User, SSHKey
import pytest


class TestSshKeys:

    _sshkey_input = {
        "public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDVbtGe1p6vAjwizqEiO"\
                    "8EY5K3jyB7NoBT+gDREp6TcimUMJzsWryJampX7IqDpkC7I2/Y7oiUudV"\
                    "R97Q6H//IckCJetaD/yONkqzRCxCoQz+J0JWlMZsS/MmIy6BHDrLYB6KB"\
                    "Z4zk6exxbxcanJnz2fHahom8GE57l9khYgm3WLGi+v3ofb6ZsT6BrR8eX"\
                    "Rpb6wJ6HcghGRwWg7+M6IMqZdprvzGomc7UO3fPmQXf3KF9ZlelNCBscz"\
                    "D4qrYshiScVqmWmo2jePTDESWaaP3jlqz7EkvfxukAuTm2spohtmVs+iw"\
                    "xOTvEwP3o7ucfp/o7QRYPqL/OPXAN8pjzf7wZ3"
    }

    _sshkeys_output = [
        {
            "public_key": foodata.sshkey1,
        },
        {
            "public_key": foodata.sshkey2,
        },
    ]

    #################################
    #### Testing GET /sshkeys
    #################################
    # Response 404: TODO after filter by user

    # Response 403: WHY ???

    # Response 401:
    def test_get_with_no_token(self, testapp):
        testapp.get(api_version + "/sshkeys", status=401)

    # Response 200:
    def test_get(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            res = testapp.get(api_version + "/sshkeys", status=200).json
            assert dict_contains(res, self._sshkeys_output)
    #################################

    #################################
    #### Testing POST /sshkeys
    #################################
    # Response 403: TODO => is it possible ?

    # Response 401:
    def test_create_with_no_token(self, testapp):
        testapp.post_json(api_version + "/sshkeys", self._sshkey_input, status=401)

    # Response 201: TODO Write test for posting raw text
    def test_create(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            res = testapp.post_json(api_version + "/sshkeys", self._sshkey_input, status=201).json
            assert dict_contains(res, self._sshkey_input)
    #################################

    #################################
    #### Testing DELETE /sshkeys/kId
    #################################
    # Response 204:
    # TODO: how to remove the header "Content-Type" in the a DELETE request only?
    @pytest.mark.filterwarnings("ignore:.*Content-Type header found in a 204 response.*:Warning")
    def test_delete_sshkey(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=fake_admin):

            # Get sshkey id
            sshkey = SSHKey.query.filter_by(public_key=foodata.sshkey1).first()
            sshkey_id = str(sshkey.id)

            # Delete this sshkey
            testapp.delete(api_version + "/sshkeys/" + sshkey_id, status=204)

            # Ensure this sshkey is not present anymore
            res = testapp.get(api_version + "/sshkeys", status=200)
            assert foodata.sshkey1 not in res

    # Response 400:
    def test_delete_bad_sshkey(self, testapp):
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            res = testapp.delete(api_version + '/sshkeys/' + bad_id, status=400).json
            assert "The browser (or proxy) sent a request that this server could not understand." in res["detail"]

    # Response 401:
    def test_delete_unauthenticated(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            # Get sshkey id
            sshkey = SSHKey.query.filter_by(public_key=foodata.sshkey1).first()
            sshkey_id = str(sshkey.id)

        # Delete this sshkey
        testapp.delete(api_version + "/sshkeys/" + sshkey_id, status=401)

    # Response 403:
    def test_delete_insufficient_rights(self, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", return_value=foobar):

            # Get sshkey id
            sshkey = SSHKey.query.filter_by(public_key=foodata.sshkey1).first()
            sshkey_id = str(sshkey.id)

        with patch.object(oidc, "validate_token", return_value=True), \
            patch("utils.check_user_role", side_effect=Forbidden):

            # Delete this sshkey
            res = testapp.delete(api_version + "/sshkeys/" + sshkey_id, status=403).json
            assert "You don't have the permission to access the requested resource." in res["detail"]
    #################################
