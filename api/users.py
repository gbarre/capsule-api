from models import RoleEnum
from models import User, user_schema, users_schema
from utils import oidc_require_role
from werkzeug.exceptions import NotFound, BadRequest
from sqlalchemy.exc import InvalidRequestError


# GET /users
@oidc_require_role(min_role=RoleEnum.admin)
def search(offset, limit, filters):
    try:
        results = User.query.filter_by(**filters)\
            .limit(limit).offset(offset).all()
    except InvalidRequestError as e:
        raise BadRequest

    if not results:
        raise NotFound(description="No users have been found.")

    return users_schema.dump(results).data


# GET /users/{uId}
@oidc_require_role(min_role=RoleEnum.admin)
def get(user_id):
    user = User.query.filter_by(name=user_id).first()

    if user is None:
        raise NotFound(description=f"The requested user '{user_id}' "
                       "has not been found.")

    return user_schema.dump(user).data
