from flask.globals import current_app
from models import RoleEnum
from utils import getClusterPartsUsage, getWebappsVolumeUsage
from utils import oidc_require_role
from werkzeug.exceptions import Forbidden


# GET /cluster
@oidc_require_role(min_role=RoleEnum.user)
def get(user):
    if (user.role is RoleEnum.user) and (not user.parts_manager):
        raise Forbidden(description='You cannot get the cluster size.')

    result = {
        "parts_assigned": getClusterPartsUsage(""),
        "total_parts": current_app.config['CLUSTER_PARTS'],
        "volumes_size_assigned": getWebappsVolumeUsage(),
        "total_volumes_size": current_app.config['VOLUMES_GLOBAL_SIZE']
    }
    return result
