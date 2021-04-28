from tests.utils import api_version, dict_contains
from app import oidc
from unittest.mock import patch
from models import user_schema


class TestMe:

    #################################
    # Testing GET /me
    #################################
    def test_get_self_user(self, testapp, db):
        user_output = user_schema.dump(db.user1)
        with patch.object(oidc, "validate_token", return_value=True), \
             patch("utils.check_user_role", return_value=db.user1):

            # Get this user by id
            user = testapp.get(
                api_version + "/me",
                status=200
            ).json
            assert dict_contains(user, user_output)
