from tests.utils import api_version
from app import oidc
from unittest.mock import patch
from nats import NATS


class TestmodelsOptions:

    # Build webapp with correct runtime_id
    @staticmethod
    def build_webapp(db):
        webapp = {
            "fqdns": [
                {
                    "name": "main.example.com",
                    "alias": False
                },
            ],
            "opts": [],
            "runtime_id": str(db.runtime4.id),
        }
        return webapp

    # Create a new capsule
    @staticmethod
    def build_capsule(db, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch("api.capsules.check_owners_on_keycloak"):

            capsule_input = {
                "name": "test-capsule",
                "owners": [
                    db.user1.name,
                ],
            }

            capsule = testapp.post_json(
                api_version + "/capsules",
                capsule_input,
                status=201
            ).json
        return capsule['id']

    def test_opt_missing_tag_key(self, testapp, db):
        capsule_id = self.build_capsule(db, testapp)
        webapp = self.build_webapp(db)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_addon_present"):

            option = {
                "field_name": "test_min_max",
                "tagg": "PHP",
                "value": "12"
            }
            webapp['opts'].append(option)

            res = testapp.post_json(
                f"{api_version}/capsules/{capsule_id}/webapp",
                webapp,
                status=400
            ).json
            msg = "'tag' is required for opts"
            assert msg in res['error_description']

    def test_unexisting_opt(self, testapp, db):
        capsule_id = self.build_capsule(db, testapp)
        webapp = self.build_webapp(db)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_addon_present"):

            option = {
                "field_name": "foobar",
                "tag": "PHP",
                "value": "12"
            }
            webapp['opts'].append(option)

            res = testapp.post_json(
                f"{api_version}/capsules/{capsule_id}/webapp",
                webapp,
                status=400
            ).json
            msg = "This option is not available: "
            assert msg in res['error_description']

    def test_opt_inscufficient_rights(self, testapp, db):
        capsule_id = self.build_capsule(db, testapp)
        webapp = self.build_webapp(db)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_addon_present"):

            option = {
                "field_name": "test_regex",
                "tag": "PHP",
                "value": "foobar"
            }
            webapp['opts'].append(option)

            res = testapp.post_json(
                f"{api_version}/capsules/{capsule_id}/webapp",
                webapp,
                status=403
            ).json
            msg = "You don't have permission to set the option 'test_regex'"
            assert msg in res['error_description']

    def test_opt_bad_regex(self, testapp, db):
        capsule_id = self.build_capsule(db, testapp)
        webapp = self.build_webapp(db)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch.object(NATS, "publish_webapp_present"):

            option = {
                "field_name": "test_regex",
                "tag": "PHP",
                "value": "4_2"
            }
            webapp['opts'].append(option)

            res = testapp.post_json(
                f"{api_version}/capsules/{capsule_id}/webapp",
                webapp,
                status=400
            ).json
            msg = f"'{option['field_name']}' must match " \
                  f"python regex {db.validation_rule3.arg}"
            assert msg in res['error_description']

    def test_opt_bad_min(self, testapp, db):
        capsule_id = self.build_capsule(db, testapp)
        webapp = self.build_webapp(db)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch.object(NATS, "publish_webapp_present"):

            option = {
                "field_name": "test_min_max",
                "tag": "PHP",
                "value": "0"
            }
            webapp['opts'].append(option)

            res = testapp.post_json(
                f"{api_version}/capsules/{capsule_id}/webapp",
                webapp,
                status=400
            ).json
            msg = f"'{option['field_name']}' cannot be " \
                  f"less than {db.validation_rule1bis.arg}"
            assert msg in res['error_description']

    def test_opt_bad_max(self, testapp, db):
        capsule_id = self.build_capsule(db, testapp)
        webapp = self.build_webapp(db)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch.object(NATS, "publish_webapp_present"):

            option = {
                "field_name": "test_min_max",
                "tag": "PHP",
                "value": "5000"
            }
            webapp['opts'].append(option)

            res = testapp.post_json(
                f"{api_version}/capsules/{capsule_id}/webapp",
                webapp,
                status=400
            ).json
            msg = f"'{option['field_name']}' cannot be " \
                  f"greater than {db.validation_rule2bis.arg}"
            assert msg in res['error_description']

    def test_opt_equal(self, testapp, db):
        capsule_id = self.build_capsule(db, testapp)
        webapp = self.build_webapp(db)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch.object(NATS, "publish_webapp_present"):

            option = {
                "field_name": "test_eq",
                "tag": "PHP",
                "value": "toto"
            }
            webapp['opts'].append(option)

            res = testapp.post_json(
                f"{api_version}/capsules/{capsule_id}/webapp",
                webapp,
                status=400
            ).json
            msg = f"'{option['field_name']}' cannot be " \
                  f"different from {db.validation_rule4.arg}"
            assert msg in res['error_description']

    def test_opt_non_equal(self, testapp, db):
        capsule_id = self.build_capsule(db, testapp)
        webapp = self.build_webapp(db)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch.object(NATS, "publish_webapp_present"):

            option = {
                "field_name": "test_neq",
                "tag": "PHP",
                "value": "barfoo"
            }
            webapp['opts'].append(option)

            res = testapp.post_json(
                f"{api_version}/capsules/{capsule_id}/webapp",
                webapp,
                status=400
            ).json
            msg = f"'{option['field_name']}' cannot be " \
                  f"equal to {db.validation_rule5.arg}"
            assert msg in res['error_description']

    def test_opt_into(self, testapp, db):
        capsule_id = self.build_capsule(db, testapp)
        webapp = self.build_webapp(db)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch.object(NATS, "publish_webapp_present"):

            option = {
                "field_name": "test_into",
                "tag": "PHP",
                "value": "barfoo"
            }
            webapp['opts'].append(option)

            res = testapp.post_json(
                f"{api_version}/capsules/{capsule_id}/webapp",
                webapp,
                status=400
            ).json
            msg = f"'{option['field_name']}' must be " \
                  f"in {db.validation_rule7.arg}"
            assert msg in res['error_description']
