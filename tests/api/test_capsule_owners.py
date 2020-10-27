from tests.utils import api_version, bad_id, unexisting_id, dict_contains
from app import oidc
from unittest.mock import patch
from exceptions import KeycloakUserNotFound
import pytest
from nats import NATS


class TestCapsuleOwners:

    _owners_input = {
        "newOwner": "tutu3",
    }
    _bad_owner_input = {
        "owner": "titi4",
    }

    @staticmethod
    def build_output(db):
        return [{"name": u.name} for u in db.capsule1.owners]

    ################################################
    # Testing GET /capsules/{cId}/owners
    ################################################
    # Response 400:
    def test_get_bad_request(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            testapp.get(
                api_version + "/capsules/" + bad_id + "/owners",
                status=400
            )

    # Response 401:
    def test_get_with_no_token(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        testapp.get(
            api_version + "/capsules/" + capsule_id + "/owners", status=401)

    # Response 403:
    def test_get_raise_bad_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            testapp.get(
                api_version + "/capsules/" + capsule_id + "/owners",
                status=403
            )

    # Response 404:
    def test_get_bad_id(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(
                api_version + "/capsules/" + unexisting_id + "/owners",
                status=404
            ).json
            msg = f"The requested capsule '{unexisting_id}' "\
                  "has not been found."
            assert msg in res["error_description"]

    # Response 200:
    def test_get(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        owners_output = self.build_output(db)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(
                api_version + "/capsules/" + capsule_id + "/owners",
                status=200
            ).json
            assert dict_contains(res, owners_output)
    ################################################

    ################################################
    # Testing PATCH /capsules/{cId}/owners
    ################################################
    # Response 400:
    def test_patch_bad_request_wrong_capsule_id(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):
            testapp.patch_json(
                api_version + "/capsules/" + bad_id + "/owners",
                self._owners_input,
                status=400
            )

    def test_patch_bad_request_wrong_input(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.patch_json(
                api_version + "/capsules/" + capsule_id + "/owners",
                self._bad_owner_input,
                status=400
            ).json
            assert "The key newOwner is required." in res["error_description"]

    # Response 401:
    def test_patch_unauthorized(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        testapp.patch_json(
            api_version + "/capsules/" + capsule_id + "/owners",
            self._owners_input,
            status=401
        )

    # Response 403:
    def test_patch_forbidden(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            testapp.patch_json(
                api_version + "/capsules/" + capsule_id + "/owners",
                self._owners_input,
                status=403
            )

    # Response 404:
    def test_patch_not_found_capsule_id(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            testapp.patch_json(
                api_version + "/capsules/" + unexisting_id + "/owners",
                self._owners_input,
                status=404
            )

    def test_patch_not_found_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch(
                 "api.capsules.owners.check_owners_on_keycloak",
                 side_effect=KeycloakUserNotFound("tutu3")):

            testapp.patch_json(
                api_version + "/capsules/" + capsule_id + "/owners",
                self._owners_input,
                status=404
            )

    # Response 409:
    def test_patch_conflict(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            new_owner = {
                "newOwner": db.user1.name
            }

            testapp.patch_json(
                api_version + "/capsules/" + capsule_id + "/owners",
                new_owner,
                status=409
            )

    # Response 200:
    def test_patch_with_unexisting_user(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch("api.capsules.owners.check_owners_on_keycloak"), \
             patch.object(NATS, "publish_webapp_present") as publish_method:

            res = testapp.patch_json(
                api_version + "/capsules/" + capsule_id + "/owners",
                self._owners_input,
                status=200
            ).json
            publish_method.assert_called_once()
            assert self._owners_input["newOwner"] in res["owners"]

    def test_patch_with_existing_user(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch("api.capsules.owners.check_owners_on_keycloak"), \
             patch.object(NATS, "publish_webapp_present") as publish_method:

            owner_input = {
                "newOwner": db.user3.name,
            }
            res = testapp.patch_json(
                api_version + "/capsules/" + capsule_id + "/owners",
                owner_input,
                status=200
            ).json
            publish_method.assert_called_once()
            assert db.user3.name in res["owners"]
    ################################################

    ################################################
    # Testing DELETE /capsules/{cId}/owners/uId
    ################################################
    # Response 400:
    def test_delete_bad_request_wrong_capsule_id(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            testapp.delete(
                api_version + "/capsules/" + bad_id + "/owners/whatever",
                status=400
            )

    # Response 401:
    def test_delete_unauthorized(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        testapp.delete(
            f"{api_version}/capsules/{capsule_id}/owners/{db.user2.name}",
            status=401
        )

    # Response 403:
    def test_delete_forbidden(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            testapp.delete(
                f"{api_version}/capsules/{capsule_id}/owners/{db.user1.name}",
                status=403
            )

    # Response 404:
    def test_delete_not_found_capsule_id(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            testapp.delete(
                f"{api_version}/capsules/{unexisting_id}/owners/whatever",
                status=404
            )

    def test_delete_invalid_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            admin = db.admin_user.name
            res = testapp.delete(
                f"{api_version}/capsules/{capsule_id}/owners/{admin}",
                status=404
            ).json
            msg = f'{admin} is not in owners.'
            assert msg in res["error_description"]

    # Response 409:
    def test_delete_conflict(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            testapp.delete(
                f"{api_version}/capsules/{capsule_id}/owners/{db.user1.name}",
                status=409
            )

    # Response 204:
    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_delete(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_present") as publish_method:

            # Delete owner
            testapp.delete(
                f"{api_version}/capsules/{capsule_id}/owners/{db.user2.name}",
                status=204
            )
            publish_method.assert_called_once()

            # Check owner is not present anymore
            res = testapp.get(
                api_version + "/capsules/" + capsule_id + "/owners",
                status=200
            ).json
            assert db.user2.name not in res
    ################################################
