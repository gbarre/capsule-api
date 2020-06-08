from flask import request
from models import RoleEnum, AppToken, apptoken_schema, apptokens_schema
from app import db
from utils import oidc_require_role
from werkzeug.exceptions import NotFound, BadRequest, Forbidden
from secrets import token_urlsafe
from hashlib import sha512


# GET /apptokens
@oidc_require_role(min_role=RoleEnum.user)
def search(offset, limit, filters, user):
    try:
        query = []
        if user.role < RoleEnum.admin:
            query.append(AppToken.user == user)
        results = AppToken.query.filter(*query).limit(limit).offset(offset).all()
    except Exception as e:
        raise e
        raise BadRequest

    if not results:
        raise NotFound(description="No apptoken have been found.")

    apptokens_data = apptokens_schema.dump(results).data
    for apptoken_data in apptokens_data:
        apptoken_data.pop('token')
    return apptokens_data


# POST /apptokens
@oidc_require_role(min_role=RoleEnum.user)
def post(user):
    apptoken_data = request.get_json()

    app = apptoken_data["app"].strip()
    if len(app) < 5:
        raise BadRequest(description="'app' length must be 5 at least.")
    token = token_urlsafe(32)
    hashed_token = sha512(token.encode('ascii')).hexdigest()

    apptoken = AppToken(app=app, owner_id=user.id, token=hashed_token)
    db.session.add(apptoken)
    db.session.commit()

    result = AppToken.query.get(apptoken.id)
    result_data = apptoken_schema.dump(result).data
    result_data["token"] = token
    return result_data, 201, {
        'Location': f'{request.base_url}/apptokens/{apptoken.id}',
    }


# DELETE /apptokens/{tId}
@oidc_require_role(min_role=RoleEnum.user)
def delete(apptoken_id, user):
    try:
        apptoken = AppToken.query.get(apptoken_id)
    except:
        raise BadRequest

    if apptoken is None:
        raise NotFound(description=f"The requested apptoken '{apptoken_id}' has not been found.")

    print(type(user.id))
    print(user.id)
    print(type(apptoken.owner_id))
    print(apptoken.owner_id)
    print(user.role)

    if (user.id != apptoken.owner_id) and (user.role < RoleEnum.admin):
        raise Forbidden

    db.session.delete(apptoken)
    db.session.commit()
    return None, 204
