# GET /capsules/{cID}/addons
@oidc.accept_token(require_token=True, render_errors=False)
def search(offset, limit, filters):
    pass

# POST /capsules/{cID}/addons
@oidc.accept_token(require_token=True, render_errors=False)
def post(addon):
    pass

# GET /capsules/{cID}/addons/{aID}
@oidc.accept_token(require_token=True, render_errors=False)
def get(addon_id):
    pass

# PUT /capsules/{cID}/addons/{aID}
@oidc.accept_token(require_token=True, render_errors=False)
def put(addon_id, addon):
    pass

# DELETE /capsules/{cID}/addons/{aID}
@oidc.accept_token(require_token=True, render_errors=False)
def delete(addon_id):
    pass