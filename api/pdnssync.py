from flask.globals import current_app
from models import Capsule, Pdnssync, pdnssync_schema, RoleEnum
from utils import oidc_require_role


# GET /pdnssync
@oidc_require_role(min_role=RoleEnum.admin)
def get(domain, exclude):
    capsules = Capsule.query.all()

    filtered_names = [
        fqdn.name
        for capsule in capsules
        for fqdn in capsule.fqdns
        if fqdn.name.endswith(domain) and all(
            not fqdn.name.endswith(excluded)
            for excluded in exclude.values()
        )
    ]

    results = []
    for fqdn in filtered_names:
        if not fqdn.endswith('.'):
            fqdn = f'{fqdn}.'
        results.append(
            Pdnssync(fqdn, 'CNAME', current_app.config['PAAS_CNAME'])
        )

    return pdnssync_schema.dump(results)
