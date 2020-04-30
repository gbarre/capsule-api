from app import oidc
from tests.utils import dict_contains

class TestCapsules:
    _capsule_input = {
        'name': 'Test Capsule',
        'owners': [
            'foobar',
            'barfoo',
            'toto',
        ]
    }

    def test_create_with_no_token(self, testapp):
        res = testapp.post_json('/v1/capsules', self._capsule_input, status=401)

    def test_create(self, testapp, db, monkeypatch):
        monkeypatch.setattr(oidc, 'validate_token',
                            lambda *args, **kwargs: True)
        monkeypatch.setattr(
            'api.capsules.check_owners_on_keycloak', lambda *args, **kwargs: None)

        res = testapp.post_json('/v1/capsules', self._capsule_input, status=201).json
        assert dict_contains(res, self._capsule_input)