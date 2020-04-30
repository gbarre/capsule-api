from app import oidc
from exceptions import KeycloakUserNotFound
from tests.utils import dict_contains
from unittest.mock import patch


class TestCapsules:
    _capsule_input = {
        'name': 'Test Capsule',
        'owners': [
            'foobar',
            'barfoo',
            'toto',
        ],
        'authorized_keys': [
            '''ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCfIjBj6woA9p+xZh8cqeiZLzN
            RARCP0Ym9gITKNgRxjRNJj+nfkBSK27A5TjL7cFFyUf1BOhY+Rwsj8wC0jt0NsbAfF
            oX+qdbqra/FC4GYwyfLfIMnZrBSjFJ0uDe5zNgDuGsvNpPAx4LA+hqdUN0iXYpMYsz
            +W9KtofeG8xbCGWHUaQPxxhralgJjkhAWxoCq7Gj92Kbb5/bvOBHpEeMdD6iDJ2zfW
            /xyRI8btllTDGzKmYVZlSHwbNje3jX4yiR2V20SlewSn07K7xykmTPsUPgpx+uysYR
            VwWUb2sWJVARfjZUzeSLrDATpxQIWYU9iY0l4cPOztnTMZN3LIBkD john@doe''',
        ]
    }

    def test_create_with_no_token(self, testapp):
        testapp.post_json('/v1/capsules', self._capsule_input, status=401)

    def test_create_raises_on_invalid_owner(self, testapp):
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch('api.capsules.check_owners_on_keycloak', side_effect=KeycloakUserNotFound('barfoo')):

            res = testapp.post_json('/v1/capsules', self._capsule_input, status=400).json
            assert 'barfoo' in res['detail']

    def test_create(self, testapp, db, monkeypatch):
        with patch.object(oidc, 'validate_token', return_value=True), \
            patch('api.capsules.check_owners_on_keycloak'):

            res = testapp.post_json('/v1/capsules', self._capsule_input, status=201).json
            assert dict_contains(res, self._capsule_input)