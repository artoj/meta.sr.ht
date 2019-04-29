from flask import redirect, abort, current_app, request
from flask_login import current_user
from functools import wraps
from metasrht.types import UserType

def adminrequired(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user:
            return redirect(current_app.oauth_service.oauth_url(request.url))
        elif current_user.user_type != UserType.admin:
            abort(403)
        else:
            return f(*args, **kwargs)
    return wrapper
