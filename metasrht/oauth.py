from metasrht.types import OAuthClient, OAuthToken, DelegatedScope
from srht.config import cfgkeys, cfg
from srht.database import db
from srht.oauth import OAuthScope, set_validator, add_alias
from functools import wraps
from datetime import datetime
from flask import request
import hashlib

meta_scopes = {
    'profile': 'profile information',
    'audit': 'audit log',
    'keys': 'SSH and PGP keys',
}

meta_access = {
    'profile': 'read',
    'audit': 'read',
    'keys': 'read',
}

add_alias("meta.sr.ht", None)
for key in cfgkeys("oauth-aliases"):
    add_alias(key, cfg("oauth-aliases", key))

def validator(self, client_id, scope, access):
    client = None
    if client_id:
        client = OAuthClient.query \
                .filter(OAuthClient.client_id == client_id).first()
        if not client:
            raise Exception('Unknown client ID {}'.format(client_id))
    self.client = client
    if not client:
        if not scope in meta_scopes:
            raise Exception('Invalid scope {}'.format(scope))
        if meta_access[scope] == 'read' and access == 'write':
            raise Exception('Write access not permitted for {}'.format(scope))
        return meta_scopes[scope]
    else:
        _scope = DelegatedScope.query\
                .filter(DelegatedScope.client_id == client.id)\
                .filter(DelegatedScope.name == scope).first()
        if not _scope:
            raise Exception('Invalid scope {}'.format(scope))
        if not _scope.write and access == 'write':
            raise Exception('Write access not permitted for {}'.format(scope))
        return _scope.description

set_validator(validator)

def oauth(scopes):
    def wrap(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = request.headers.get('Authorization')
            if not token or not token.startswith('token '):
                return { "errors": [ { "reason": "No authorization supplied (expected an OAuth token)" } ] }, 401
            token = token.split(' ')
            if len(token) != 2:
                return { "errors": [ { "reason": "Invalid authorization supplied" } ] }, 401
            token = token[1]
            h = hashlib.sha512(token.encode()).hexdigest()
            oauth_token = OAuthToken.query.filter(OAuthToken.token_hash == h).first()
            if not oauth_token:
                return { "errors": [ { "reason": "Invalid or expired OAuth token" } ] }, 401
            if oauth_token.expires < datetime.utcnow():
                return { "errors": [ { "reason": "Invalid or expired OAuth token" } ] }, 401
            args = (oauth_token,) + args
            if oauth_token.scopes == '*':
                return f(*args, **kwargs)
            required = OAuthScope(scopes)
            available = [OAuthScope(s) for s in oauth_token.scopes.split(',')]
            applicable = [
                s for s in available
                if s.client_id == required.client_id and s.scope == required.scope
            ]
            if not any(applicable):
                return { "errors": [ { "reason": "Your OAuth token is not permitted to use this endpoint (needs {})".format(required) } ] }, 403
            if required.access == 'read' and any([s for s in applicable if s.access == 'read' or s.access == 'write']):
                return f(*args, **kwargs)
            if required.access == 'write' and any([s for s in applicable if s.access == 'write']):
                return f(*args, **kwargs)
            oauth_token.updated = datetime.utcnow()
            db.session.commit()
            return { "errors": [ { "reason": "Your OAuth token is not permitted to use this endpoint (needs {})".format(required) } ] }, 403
        return wrapper
    return wrap
