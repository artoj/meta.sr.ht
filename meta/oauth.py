from meta.types import OAuthClient

aliases = {
    'meta.sr.ht': None,
    'git.sr.ht': 'todo',
}

meta_scopes = {
    'profile': 'profile information',
    'audit': 'audit log',
    'keys': 'SSH and PGP keys',
}

class OAuthScope:
    def __init__(self, scope):
        client = None
        access = 'read'
        if '/' in scope:
            i = scope.index('/')
            client = scope[:i]
            scope = scope[i + 1:]
        if ':' in scope:
            i = scope.index(':')
            access = scope[i + 1:]
            scope = scope[:i]
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
                raise Exception('Invalid scope {}'.format(access))
        else:
            pass # TODO: Check for third party scopes
        self.client = client
        self.scope = scope
        self.access = access

    def __repr__(self):
        return '{}/{}:{}'.format(self.client, self.scope, self.access)

    def readver(self):
        return '{}/{}:{}'.format(self.client, self.scope, 'read')

    def friendly(self):
        if self.client == None:
            return meta_scopes[self.scope]
        else:
            pass # TODO: third party scopes
