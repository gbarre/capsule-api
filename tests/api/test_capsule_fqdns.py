from tests.utils import api_version, bad_id, unexisting_id, dict_contains
from app import oidc
from unittest.mock import patch
from models import fqdn_schema
import json
import pytest
from nats import NATS


#
# DISCLAIMER : key and cert in this file are only used for tests
#              DO NOT USE THEM IN PRODUCTION ENVIRONMENT
class TestCapsuleFqdns:

    _fqdn_input = {
        "name": "sub.secondary.my-example.com",
        "alias": True
    }

    @staticmethod
    def build_output(db):
        fqdn = json.loads(fqdn_schema.dumps(db.fqdn1))
        return fqdn

    ################################################
    # Testing POST /capsules/{cId}/fqdns
    ################################################
    # Response 201:
    def test_create(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch.object(NATS, "publish_webapp_present") as publish_method:
            capsule_id = str(db.capsule1.id)

            # Create fqdn
            res = testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/fqdns',
                self._fqdn_input,
                status=201
            ).json
            publish_method.assert_called_once()

            assert dict_contains(res, self._fqdn_input)

    # Response 400:
    def test_create_bad_capsule_id(self, testapp, db):
        with patch.object(oidc, 'validate_token', return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):

            res = testapp.post_json(
                api_version + '/capsules/' + bad_id + '/fqdns',
                self._fqdn_input,
                status=400
            ).json
            msg = f"'{bad_id}' is not a valid id."
            assert msg in res['error_description']

    def test_create_fqdn_already_exists(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):
            capsule_id = str(db.capsule1.id)

            # Create webapp
            new_fqdn = {
                "name": "main.fqdn.ac-versailles.fr",
                "alias": True
            }

            res = testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/fqdns',
                new_fqdn,
                status=400
            ).json
            msg = f'{new_fqdn["name"]} already exists.'
            assert msg in res['error_description']

    def test_create_primary_fqdn(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):
            capsule_id = str(db.capsule1.id)

            # Create webapp
            new_fqdn = {
                "name": "other.fqdn.ac-versailles.fr",
                "alias": False
            }

            res = testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/fqdns',
                new_fqdn,
                status=400
            ).json
            msg = "Only one primary FQDN by capsule"
            assert msg in res['error_description']

    # Response 401:
    def test_create_with_no_token(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        testapp.post_json(
            api_version + '/capsules/' + capsule_id + '/fqdns',
            self._fqdn_input,
            status=401
        )

    # Response 403:
    def test_create_bad_owner(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):
            capsule_id = str(db.capsule1.id)

            testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/fqdns',
                self._fqdn_input,
                status=403
            )

    def test_create_without_delegate(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_absent"), \
             patch.object(NATS, "publish_webapp_present"):
            capsule_id = str(db.capsule1.id)

            # Create fqdn
            testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/fqdns',
                self._fqdn_input,
                status=403
            )

    # Response 404:
    def test_create_unexisting_capsule_id(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            res = testapp.post_json(
                api_version + '/capsules/' + unexisting_id + '/fqdns',
                self._fqdn_input,
                status=404
            ).json
            msg = f"The requested capsule '{unexisting_id}' "\
                  "has not been found."
            assert msg in res['error_description']
    ################################################

    ################################################
    # Testing PUT /capsules/{cId}/fqdns/{fId}
    ################################################
    # Response 200:
    def test_update(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        fqdn_id = str(db.fqdn1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch.object(NATS, "publish_webapp_present") as publish_method:

            current_fqdn = self.build_output(db)
            current_fqdn['name'] = "new.fqdn.com"
            current_fqdn.pop('id')

            res = testapp.put_json(
                f'{api_version}/capsules/{capsule_id}/fqdns/{fqdn_id}',
                current_fqdn,
                status=200
            ).json
            publish_method.assert_called_once()
            assert dict_contains(res, current_fqdn)

    # Response 400:
    def test_update_bad_request(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):

            testapp.put_json(
                f'{api_version}/capsules/{capsule_id}/fqdns/{bad_id}',
                self._fqdn_input,
                status=400
            )

    def test_update_repeat_fqdn(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        fqdn_id = str(db.fqdn1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):

            current_fqdn = self.build_output(db)
            current_fqdn['name'] = "secondary.fqdn.ac-versailles.fr"
            current_fqdn.pop('id')

            res = testapp.put_json(
                f'{api_version}/capsules/{capsule_id}/fqdns/{fqdn_id}',
                current_fqdn,
                status=400
            ).json
            msg = f"'{current_fqdn['name']}' already exists."
            assert msg in res['error_description']

    def test_update_primary_fqdn(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        fqdn2 = json.loads(fqdn_schema.dumps(db.fqdn2))
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):

            fqdn2_id = str(fqdn2['id'])
            fqdn2.pop('id')
            fqdn2['alias'] = False

            res = testapp.put_json(
                f'{api_version}/capsules/{capsule_id}/fqdns/{fqdn2_id}',
                fqdn2,
                status=400
            ).json
            msg = "Only one primary FQDN by capsule"
            assert msg in res['error_description']

    # Response 401:
    def test_update_unauthenticated(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        current_fqdn = self.build_output(db)
        fqdn_id = current_fqdn['id']

        testapp.put_json(
            f'{api_version}/capsules/{capsule_id}/fqdns/{fqdn_id}',
            self._fqdn_input,
            status=401
        )

    # Response 403:
    def test_update_bad_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        current_fqdn = self.build_output(db)
        fqdn_id = current_fqdn['id']
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            testapp.put_json(
                f'{api_version}/capsules/{capsule_id}/fqdns/{fqdn_id}',
                self._fqdn_input,
                status=403
            )

    def test_update_no_delegate(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        current_fqdn = self.build_output(db)
        fqdn_id = current_fqdn['id']
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            testapp.put_json(
                f'{api_version}/capsules/{capsule_id}/fqdns/{fqdn_id}',
                self._fqdn_input,
                status=403
            )

    # Response 404:
    def test_update_unexisting_fqdn(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):

            res = testapp.put_json(
                f'{api_version}/capsules/{capsule_id}/fqdns/{unexisting_id}',
                self._fqdn_input,
                status=404
            ).json
            msg = f"The requested FQDN '{unexisting_id}' has not been found."
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
        fqdn_id = str(db.fqdn1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch.object(NATS, "publish_webapp_present") as publish_method:

            # Delete webapp
            testapp.delete(
                f'{api_version}/capsules/{capsule_id}/fqdns/{fqdn_id}',
                status=204
            )
            publish_method.assert_called_once()

    # Response 400:
    def test_delete_bad_id(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):

            testapp.delete(
                f'{api_version}/capsules/{capsule_id}/fqdns/{bad_id}',
                status=400
            )

    # Response 401:
    def test_delete_unauthorized(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        fqdn_id = str(db.fqdn1.id)
        testapp.delete(
            f'{api_version}/capsules/{capsule_id}/fqdns/{fqdn_id}',
            status=401
        )

    # Response 403:
    def test_delete_bad_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        fqdn_id = str(db.fqdn1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            testapp.delete(
                f'{api_version}/capsules/{capsule_id}/fqdns/{fqdn_id}',
                status=403
            )

    def test_delete_no_delegate(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        fqdn_id = str(db.fqdn1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            testapp.delete(
                f'{api_version}/capsules/{capsule_id}/fqdns/{fqdn_id}',
                status=403
            )

    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_delete_no_more_fqdn(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        fqdn_id1 = str(db.fqdn1.id)
        fqdn_id2 = str(db.fqdn2.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch.object(NATS, "publish_webapp_present"):

            # delete fqdn 1
            testapp.delete(
                f'{api_version}/capsules/{capsule_id}/fqdns/{fqdn_id1}',
                status=204
            )

            # try delete fqdn 2
            res = testapp.delete(
                f'{api_version}/capsules/{capsule_id}/fqdns/{fqdn_id2}',
                status=403
            ).json
            msg = "A webapp need at least one FQDN."
            assert msg in res['error_description']

    # Response 404:
    def test_delete_not_found_fqdn(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):

            testapp.delete(
                f'{api_version}/capsules/{capsule_id}/fqdns/{unexisting_id}',
                status=404
            )
    ################################################
