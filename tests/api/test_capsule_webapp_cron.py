from tests.utils import api_version, bad_id, unexisting_id, dict_contains
from app import oidc
from unittest.mock import patch
from models import cron_schema
import json
import pytest
from nats import NATS


class TestCapsuleWepappCron:

    _cron_input = {
        "command": "/usr/bin/php /app/data/www/admin/cli/cron.php",
        "hour": "*",
        "minute": "15",
        "month": "*",
        "month_day": "*",
        "week_day": "5"
    }

    @staticmethod
    def build_output(db):
        cron = json.loads(cron_schema.dumps(db.cron1).data)
        return cron

    # Create a temp capsule
    @staticmethod
    def build_temp_capsule(db, testapp):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user), \
             patch.object(NATS, "publish_webapp_present"), \
             patch("api.capsules.check_owners_on_keycloak"):

            _capsule_input = {
                "name": "temp-capsule",
                "owners": [
                    "user1",
                ],
            }

            temp_capsule = testapp.post_json(
                api_version + "/capsules",
                _capsule_input,
                status=201
            ).json

            # Create webapp for this capsule
            new_webapp = {
                "fqdns": [
                    {
                        "name": "main.example.com",
                        "alias": False
                    }
                ],
                "runtime_id": str(db.runtime1.id)
            }
            capsule_id = temp_capsule['id']
            testapp.post_json(
                api_version + '/capsules/' + capsule_id + '/webapp',
                new_webapp,
                status=201
            )

            capsule = testapp.get(
                api_version + "/capsules/" + capsule_id,
                status=200
            ).json

        return capsule

    #####################################################
    # Testing GET /capsules/{cId}/webapp/crons
    #####################################################
    # Response 200:
    def test_get(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        cron_output = self.build_output(db)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(
                f"{api_version}/capsules/{capsule_id}/webapp/crons",
                status=200
            ).json
            assert dict_contains(res[0], cron_output)

    # Response 400:
    def test_get_invalid_capsule_id(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(
                f"{api_version}/capsules/{bad_id}/webapp/crons",
                status=400
            ).json
            msg = f"'{bad_id}' is not a valid id."
            assert msg in res['error_description']

    def test_get_bad_filters(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            base_uri = f"{api_version}/capsules/{capsule_id}/webapp/crons"
            testapp.get(
                f"{base_uri}?filters[foo]=bar",
                status=400
            )

    # Response 401:
    def test_get_with_no_token(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        testapp.get(
            f"{api_version}/capsules/{capsule_id}/webapp/crons",
            status=401
        )

    # Response 403:
    def test_get_bad_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            testapp.get(
                f"{api_version}/capsules/{capsule_id}/webapp/crons",
                status=403
            )

    # Response 404:
    def test_get_unexisting_capsule_id(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(
                f"{api_version}/capsules/{unexisting_id}/webapp/crons",
                status=404
            ).json
            msg = f"The requested capsule '{unexisting_id}' has not been found"
            assert msg in res['error_description']

    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_get_capsule_without_webapp(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_absent"):

            # Remove existing webapp
            testapp.delete(
                api_version + '/capsules/' + capsule_id + '/webapp',
                status=204
            )

            res = testapp.get(
                f"{api_version}/capsules/{capsule_id}/webapp/crons",
                status=404
            ).json
            msg = "This capsule does not have webapp."
            assert msg in res['error_description']

    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_get_not_found(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        cron_id = str(db.cron1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_present"):

            # Remove existing cron
            testapp.delete(
                f"{api_version}/capsules/{capsule_id}/webapp/crons/{cron_id}",
                status=204
            )

            res = testapp.get(
                f"{api_version}/capsules/{capsule_id}/webapp/crons",
                status=404
            ).json
            msg = "No crons have been found."
            assert msg in res['error_description']

    #####################################################
    # Testing POST /capsules/{cId}/webapp/crons
    #####################################################
    # Response 201:
    def test_create(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_present") as publish_method:

            res = testapp.post_json(
                f"{api_version}/capsules/{capsule_id}/webapp/crons",
                self._cron_input,
                status=201
            ).json
            publish_method.assert_called_once
            assert dict_contains(res, self._cron_input)

    # Response 400:
    def test_create_invalid_capsule_id(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.post_json(
                f"{api_version}/capsules/{bad_id}/webapp/crons",
                self._cron_input,
                status=400
            ).json
            msg = f"'{bad_id}' is not a valid id."
            assert msg in res['error_description']

    # Response 401:
    def test_create_with_no_token(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        testapp.post_json(
            f"{api_version}/capsules/{capsule_id}/webapp/crons",
            self._cron_input,
            status=401
        )

    # Response 403:
    def test_create_bad_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            testapp.post_json(
                f"{api_version}/capsules/{capsule_id}/webapp/crons",
                self._cron_input,
                status=403
            )

    # Response 404:
    def test_create_unexisting_capsule_id(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.post_json(
                f"{api_version}/capsules/{unexisting_id}/webapp/crons",
                self._cron_input,
                status=404
            ).json
            msg = f"The requested capsule '{unexisting_id}' has not been found"
            assert msg in res['error_description']

    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_create_capsule_without_webapp(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_absent"):

            # Remove existing webapp
            testapp.delete(
                api_version + '/capsules/' + capsule_id + '/webapp',
                status=204
            )

            res = testapp.post_json(
                f"{api_version}/capsules/{capsule_id}/webapp/crons",
                self._cron_input,
                status=404
            ).json
            msg = "This capsule does not have webapp."
            assert msg in res['error_description']

    #####################################################
    # Testing GET /capsules/{cId}/webapp/crons/{crId}
    #####################################################
    # Response 200:
    def test_get_cron(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        cron_id = str(db.cron1.id)
        cron_output = self.build_output(db)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(
                f"{api_version}/capsules/{capsule_id}/webapp/crons/{cron_id}",
                status=200
            ).json
            assert dict_contains(res, cron_output)

    # Response 400:
    def test_get_cron_invalid_capsule_id(self, testapp, db):
        cron_id = str(db.cron1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(
                f"{api_version}/capsules/{bad_id}/webapp/crons/{cron_id}",
                status=400
            ).json
            msg = f"'{bad_id}' is not a valid id."
            assert msg in res['error_description']

    def test_get_cron_invalid_cron_id(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(
                f"{api_version}/capsules/{capsule_id}/webapp/crons/{bad_id}",
                status=400
            ).json
            msg = f"'{bad_id}' is not a valid id."
            assert msg in res['error_description']

    # Response 401:
    def test_get_cron_with_no_token(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        cron_id = str(db.cron1.id)

        testapp.get(
            f"{api_version}/capsules/{capsule_id}/webapp/crons/{cron_id}",
            status=401
        )

    # Response 403:
    def test_get_cron_bad_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        cron_id = str(db.cron1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            testapp.get(
                f"{api_version}/capsules/{capsule_id}/webapp/crons/{cron_id}",
                status=403
            )

    def test_get_cron_in_wrong_capsule(self, testapp, db):
        temp_capsule = self.build_temp_capsule(db, testapp)
        capsule_id = temp_capsule['id']
        cron_id = str(db.cron1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            testapp.get(
                f"{api_version}/capsules/{capsule_id}/webapp/crons/{cron_id}",
                status=403
            )

    # Response 404:
    def test_get_cron_unexisting_capsule_id(self, testapp, db):
        cron_id = str(db.cron1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            base_uri = f"{api_version}/capsules/{unexisting_id}/webapp/crons"
            res = testapp.get(
                f"{base_uri}/{cron_id}",
                status=404
            ).json
            msg = f"The requested capsule '{unexisting_id}' has not been found"
            assert msg in res['error_description']

    def test_get_cron_unexisting_id(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            base_uri = f"{api_version}/capsules/{capsule_id}/webapp/crons"
            res = testapp.get(
                f"{base_uri}/{unexisting_id}",
                status=404
            ).json
            msg = f"The requested cron '{unexisting_id}' has not been found"
            assert msg in res['error_description']

    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_get_cron_capsule_without_webapp(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        cron_id = str(db.cron1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_absent"):

            # Remove existing webapp
            testapp.delete(
                api_version + '/capsules/' + capsule_id + '/webapp',
                status=204
            )

            res = testapp.get(
                f"{api_version}/capsules/{capsule_id}/webapp/crons/{cron_id}",
                status=404
            ).json
            msg = "This capsule does not have webapp."
            assert msg in res['error_description']

    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_get_cron_not_found(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        cron_id = str(db.cron1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_present"):

            # Remove existing cron
            testapp.delete(
                f"{api_version}/capsules/{capsule_id}/webapp/crons/{cron_id}",
                status=204
            )

            res = testapp.get(
                f"{api_version}/capsules/{capsule_id}/webapp/crons/{cron_id}",
                status=404
            ).json
            msg = f"The requested cron '{cron_id}' has not been found."
            assert msg in res['error_description']

    #####################################################
    # Testing PUT /capsules/{cId}/webapp/crons/{crId}
    #####################################################
    # Response 200:
    def test_update_cron(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        cron_id = str(db.cron1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_present") as publish_method:

            cron = dict(self._cron_input)
            base_uri = f"{api_version}/capsules/{capsule_id}/webapp/crons"
            res = testapp.put_json(
                f"{base_uri}/{cron_id}",
                cron,
                status=200
            ).json
            publish_method.assert_called_once
            assert dict_contains(res, cron)

    def test_update_cron_with_only_command(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        cron_id = str(db.cron1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_present") as publish_method:

            cron = {"command": "test"}
            base_uri = f"{api_version}/capsules/{capsule_id}/webapp/crons"
            res = testapp.put_json(
                f"{base_uri}/{cron_id}",
                cron,
                status=200
            ).json
            publish_method.assert_called_once
            assert dict_contains(res, cron)

    # Response 201:
    # TODO

    # Response 400:
    def test_update_invalid_capsule_id(self, testapp, db):
        cron_id = str(db.cron1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            cron = dict(self._cron_input)
            base_uri = f"{api_version}/capsules/{bad_id}/webapp/crons"
            res = testapp.put_json(
                f"{base_uri}/{cron_id}",
                cron,
                status=400
            ).json
            msg = f"'{bad_id}' is not a valid id."
            assert msg in res['error_description']

    def test_update_invalid_cron_id(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            cron = dict(self._cron_input)
            base_uri = f"{api_version}/capsules/{capsule_id}/webapp/crons"
            res = testapp.put_json(
                f"{base_uri}/{bad_id}",
                cron,
                status=400
            ).json
            msg = f"'{bad_id}' is not a valid id."
            assert msg in res['error_description']

    # Response 401:
    def test_update_with_no_token(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        cron_id = str(db.cron1.id)

        cron = dict(self._cron_input)
        base_uri = f"{api_version}/capsules/{capsule_id}/webapp/crons"
        testapp.put_json(
            f"{base_uri}/{cron_id}",
            cron,
            status=401
        )

    # Response 403:
    def test_update_bad_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        cron_id = str(db.cron1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            cron = dict(self._cron_input)
            base_uri = f"{api_version}/capsules/{capsule_id}/webapp/crons"
            testapp.put_json(
                f"{base_uri}/{cron_id}",
                cron,
                status=403
            )

    def test_update_cron_in_wrong_capsule(self, testapp, db):
        temp_capsule = self.build_temp_capsule(db, testapp)
        capsule_id = temp_capsule['id']
        cron_id = str(db.cron1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            cron = dict(self._cron_input)
            base_uri = f"{api_version}/capsules/{capsule_id}/webapp/crons"
            testapp.put_json(
                f"{base_uri}/{cron_id}",
                cron,
                status=403
            )

    # Response 404:
    def test_update_unexisting_capsule_id(self, testapp, db):
        cron_id = str(db.cron1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            cron = dict(self._cron_input)
            base_uri = f"{api_version}/capsules/{unexisting_id}/webapp/crons"
            res = testapp.put_json(
                f"{base_uri}/{cron_id}",
                cron,
                status=404
            ).json
            msg = f"The requested capsule '{unexisting_id}' has not been found"
            assert msg in res['error_description']

    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_update_capsule_without_webapp(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        cron_id = str(db.cron1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_absent"):

            # Remove existing webapp
            testapp.delete(
                api_version + '/capsules/' + capsule_id + '/webapp',
                status=204
            )

            cron = dict(self._cron_input)
            base_uri = f"{api_version}/capsules/{capsule_id}/webapp/crons"
            res = testapp.put_json(
                f"{base_uri}/{cron_id}",
                cron,
                status=404
            ).json
            msg = "This capsule does not have webapp."
            assert msg in res['error_description']

    def test_update_unexisting_cron(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            cron = dict(self._cron_input)
            base_uri = f"{api_version}/capsules/{capsule_id}/webapp/crons"
            res = testapp.put_json(
                f"{base_uri}/{unexisting_id}",
                cron,
                status=404
            ).json
            msg = f"The requested cron '{unexisting_id}' has not been found."
            assert msg in res['error_description']

    #####################################################
    # Testing DELETE /capsules/{cId}/webapp/crons/{crId}
    #####################################################
    # Response 204:
    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_delete_cron(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        cron_id = str(db.cron1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_present")as publish_method:

            # Remove existing cron
            testapp.delete(
                f"{api_version}/capsules/{capsule_id}/webapp/crons/{cron_id}",
                status=204
            )
            publish_method.assert_called_once

    # Response 400:
    def test_delete_cron_invalid_id(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):
            # Remove existing cron
            res = testapp.delete(
                f"{api_version}/capsules/{capsule_id}/webapp/crons/{bad_id}",
                status=400
            ).json
            msg = f"'{bad_id}' is not a valid id."
            assert msg in res['error_description']

    # Response 401:
    def test_delete_with_no_token(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        cron_id = str(db.cron1.id)

        base_uri = f"{api_version}/capsules/{capsule_id}/webapp/crons"
        testapp.delete(
            f"{base_uri}/{cron_id}",
            status=401
        )

    # Response 403:
    def test_delete_bad_owner(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        cron_id = str(db.cron1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user3):

            base_uri = f"{api_version}/capsules/{capsule_id}/webapp/crons"
            testapp.delete(
                f"{base_uri}/{cron_id}",
                status=403
            )

    def test_delete_cron_in_wrong_capsule(self, testapp, db):
        temp_capsule = self.build_temp_capsule(db, testapp)
        capsule_id = temp_capsule['id']
        cron_id = str(db.cron1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            base_uri = f"{api_version}/capsules/{capsule_id}/webapp/crons"
            testapp.delete(
                f"{base_uri}/{cron_id}",
                status=403
            )

    # Response 404:
    def test_delete_unexisting_capsule_id(self, testapp, db):
        cron_id = str(db.cron1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            base_uri = f"{api_version}/capsules/{unexisting_id}/webapp/crons"
            res = testapp.delete(
                f"{base_uri}/{cron_id}",
                status=404
            ).json
            msg = f"The requested capsule '{unexisting_id}' has not been found"
            assert msg in res['error_description']

    @pytest.mark.filterwarnings(
        "ignore:.*Content-Type header found in a 204 response.*:Warning"
    )
    def test_delete_capsule_without_webapp(self, testapp, db):
        capsule_id = str(db.capsule1.id)
        cron_id = str(db.cron1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1), \
             patch.object(NATS, "publish_webapp_absent"):

            # Remove existing webapp
            testapp.delete(
                api_version + '/capsules/' + capsule_id + '/webapp',
                status=204
            )

            base_uri = f"{api_version}/capsules/{capsule_id}/webapp/crons"
            res = testapp.delete(
                f"{base_uri}/{cron_id}",
                status=404
            ).json
            msg = "This capsule does not have webapp."
            assert msg in res['error_description']

    def test_delete_unexisting_cron(self, testapp, db):
        capsule_id = str(db.capsule1.id)

        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            base_uri = f"{api_version}/capsules/{capsule_id}/webapp/crons"
            res = testapp.delete(
                f"{base_uri}/{unexisting_id}",
                status=404
            ).json
            msg = "This cron is not present in this webapp"
            assert msg in res['error_description']
