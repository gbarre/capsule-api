from app import db, oidc

# GET /runtimes
@oidc.accept_token(require_token=True, render_errors=False)
def search(offset, limit, filters):
    pass

# GET /runtimes/{rID}
@oidc.accept_token(require_token=True, render_errors=False)
def get(runtime_id):
    pass

# POST /runtimes
@oidc.accept_token(require_token=True, render_errors=False)
def post(runtime):
    pass

# PUT /runtimes/{rId}
@oidc.accept_token(require_token=True, render_errors=False)
def put(runtime_id, runtime):
    pass

# DELETE /runtimes/{rId}
@oidc.accept_token(require_token=True, render_errors=False)
def delete(runtime_id):
    pass
