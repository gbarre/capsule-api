# /GET /capsules/{cId}/owners
@oidc.accept_token(require_token=True, render_errors=False)
def search(offset, limit, filters):
    pass

# /PATCH /capsules/{cId}/owners
@oidc.accept_token(require_token=True, render_errors=False)
def patch(user_id, user):
    pass

# /DELETE /capsules/{cId}/owners/{uId}
@oidc.accept_token(require_token=True, render_errors=False)
def delete(user):
    pass