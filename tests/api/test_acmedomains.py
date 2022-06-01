from tests.utils import api_version
from app import oidc
from unittest.mock import patch


class TestAcmeDomains:

    #################################
    # Testing GET /acmedomains
    #################################
    def test_get_acmedomains(self, testapp, db):
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            domains = testapp.get(
                api_version + "/acmedomains",
                status=200
            ).json

            assert "nip.io" in domains  # Defined in config-test.yml
