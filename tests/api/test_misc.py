from models import RoleEnum

class TestMisc:

  def test_roles_power(self):
    assert RoleEnum.user < RoleEnum.admin
    assert RoleEnum.admin < RoleEnum.superadmin
