from models import RoleEnum
from models import User, user_schema, users_schema
from utils import oidc_require_role
from werkzeug.exceptions import BadRequest, Forbidden, NotFound
from sqlalchemy.exc import InvalidRequestError


# GET /users
@oidc_require_role(min_role=RoleEnum.user)
def search(offset, limit, filters, user):
    if user.role < RoleEnum.admin:
        results = [user]
    else:
        try:
            results = User.query.filter_by(**filters)\
                .limit(limit).offset(offset).all()
        except InvalidRequestError:
            raise BadRequest

    # Impossible since at least the admin (or superadmin) that is requesting
    # must be in database. Even if it has been manually removed, the
    # oidc_require_role decorator will recreate the user.
    # if not results:
    #     raise NotFound(description="No users have been found.")

    return users_schema.dump(results).data


# GET /users/{uId}
@oidc_require_role(min_role=RoleEnum.user)
def get(user_id, user):
    requested_user = User.query.filter_by(name=user_id).first()

    if requested_user is None:
        raise NotFound(description=f"The requested user '{user_id}' "
                                   "has not been found.")

    if (user.role == RoleEnum.user) and (user.name != user_id):
        raise Forbidden

    return user_schema.dump(requested_user).data
