from metasrht.types import OAuthClient, OAuthToken
from srht.database import db
from functools import wraps
from datetime import datetime
from flask import request
import hashlib

aliases = {
    'meta.sr.ht': None,
    'git.sr.ht': 'todo',
}

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

class OAuthScope:
    def __init__(self, scope):
        client = None
        access = 'read'
        if '/' in scope:
            s = scope.split('/')
            if len(s) != 2:
                raise Exception('Invalid OAuth scope syntax')
            client = s[0]
            scope = s[1]
        if ':' in scope:
            s = scope.split(':')
            if len(s) != 2:
                raise Exception('Invalid OAuth scope syntax')
            scope = s[0]
            access = s[1]
        if client in aliases:
            client = aliases[client]
        if client:
            c = OAuthClient.query \
                    .filter(OAuthClient.client_id == client).first()
            if not c:
                raise Exception('Unknown client ID {}'.format(client))
            client = c
        if not access in ['read', 'write']:
            raise Exception('Invalid scope access {}'.format(access))
        if not client:
            if not scope in meta_scopes:
                raise Exception('Invalid scope {}'.format(scope))
            if meta_access[scope] == 'read' and access == 'write':
                raise Exception('Write access not permitted for {}'.format(scope))
        else:
            pass # TODO: Check for third party scopes
        self.client = client
        self.scope = scope
        self.access = access

    def __eq__(self, other):
        return self.client == other.client \
                and self.access == other.access \
                and self.scope == other.scope

    def __repr__(self):
        if self.client:
            return '{}/{}:{}'.format(self.client.client_id, self.scope, self.access)
        return '{}:{}'.format(self.scope, self.access)

    def readver(self):
        if self.client:
            return '{}/{}:{}'.format(self.client.client_id, self.scope, 'read')
        return '{}:{}'.format(self.scope, 'read')

    def friendly(self):
        if self.client == None:
            return meta_scopes[self.scope]
        else:
            pass # TODO: third party scopes

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
            applicable = [s for s in available if s.client == required.client and s.scope == required.scope]
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
