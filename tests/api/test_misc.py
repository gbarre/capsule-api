from models import RoleEnum


class TestMisc:

    def test_roles_power(self):
        assert RoleEnum.user < RoleEnum.admin
        assert RoleEnum.superadmin > RoleEnum.user
        assert RoleEnum.admin <= RoleEnum.superadmin
        assert RoleEnum.superadmin >= RoleEnum.superadmin
