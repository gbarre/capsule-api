from tests.utils import api_version
from app import oidc
from unittest.mock import patch


class TestMe:

    #################################
    # Testing GET /cluster
    #################################
    # Response 200:
    def test_get_cluster(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):

            cluster = testapp.get(
                api_version + "/cluster",
                status=200
            ).json

            assert cluster['total_parts'] == 30  # Defined in config-test.yml
            assert cluster['total_volumes_size'] == 250

    # Response 403:
    def test_get_cluster_no_manager(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            res = testapp.get(
                api_version + "/cluster",
                status=403
            ).json

            msg = 'You cannot get the cluster size.'
            assert msg in res['error_description']
