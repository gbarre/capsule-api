# /POST /capsules/{cId}/webapp
@oidc.accept_token(require_token=True, render_errors=False)
def post(webapp):
    pass

# /GET /capsules/{cId}/webapp
@oidc.accept_token(require_token=True, render_errors=False)
def get(webapp_id):
    pass

# /PUT /capsules/{cId}/webapp
@oidc.accept_token(require_token=True, render_errors=False)
def put(webapp_id, webapp):
    pass

# /DELETE /capsules/{cId}/webapp
@oidc.accept_token(require_token=True, render_errors=False)
def delete(webapp_id):
    pass