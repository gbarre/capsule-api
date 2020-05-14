# /GET /sshkeys
@oidc.accept_token(require_token=True, render_errors=False)
def search(offset, limit, filters):
    pass

# /POST /sshkeys/{skId}
@oidc.accept_token(require_token=True, render_errors=False)
def post(sshkey):
    pass

# /DELETE /sshkeys/{skId}
@oidc.accept_token(require_token=True, render_errors=False)
def delete(sshkey_id):
    pass
