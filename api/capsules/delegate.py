from flask import request
from models import capsule_output_schema, RoleEnum, Capsule
from app import db
from utils import oidc_require_role
from werkzeug.exceptions import NotFound, BadRequest
from sqlalchemy.exc import StatementError


# PATCH /capsules/{cID}/delegate
@oidc_require_role(min_role=RoleEnum.admin)
def patch(capsule_id):
    try:
        capsule = Capsule.query.filter_by(id=capsule_id).first()
    except StatementError:
        raise BadRequest(description=f"'{capsule_id}' is not a valid id.")

    if capsule is None:
        raise NotFound(description=f"The requested capsule '{capsule_id}' "
                       "has not been found.")

    data = request.get_json()

    if 'fqdns' in data:
        capsule.delegate_fqdns = data['fqdns']

    if 'tls' in data:
        capsule.delegate_tls = data['tls']

    db.session.commit()

    result = capsule_output_schema.dump(capsule)
    return result, 200, {
        'Location': f'{request.base_url}/capsules/{capsule.id}',
    }
