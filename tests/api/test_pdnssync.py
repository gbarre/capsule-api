from tests.utils import api_version
from app import oidc
from unittest.mock import patch


class TestPdnssync:

    #################################
    # Testing GET /pdnssync
    #################################
    def test_get_pdnssync(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.admin_user):

            results = testapp.get(
                api_version + '/pdnssync?domain=.fr',
                status=200
            ).json

            assert "main.fqdn.ac-versailles.fr." == results[0]['name']
