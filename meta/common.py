from flask import redirect, request, abort
from flask_login import current_user
from functools import wraps
from meta.types import UserType

import urllib

def loginrequired(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user or current_user.user_type == UserType.unconfirmed:
            return redirect("/login?return_to=" + urllib.parse.quote_plus(request.url))
        else:
            return f(*args, **kwargs)
    return wrapper

def adminrequired(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user or current_user.user_type != UserType.admin:
            return redirect("/login?return_to=" + urllib.parse.quote_plus(request.url))
        else:
            if not current_user.admin:
                abort(401)
            return f(*args, **kwargs)
