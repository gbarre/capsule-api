# GET /users
@oidc_require_role(min_role=RoleEnum.admin)
def search(offset, limit, filters):
    pass

# GET /users/{uId}
@oidc_require_role(min_role=RoleEnum.admin)
def get(user_id):
    pass