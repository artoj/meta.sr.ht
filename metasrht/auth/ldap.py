import sys

from srht.config import cfg, cfgb
from srht.database import db
from srht.validation import Validation

from metasrht.audit import audit_log
from metasrht.auth.base import AuthMethod, get_user
from metasrht.auth_validation import *
from metasrht.types import User, UserType

# FIXME: LDAP connection management could be improved:
#   * We keep a connection (self.conn) open for browsing the LDAP tree,
#     changing passwords and emails: what happen if this connection is closed
#     (e.g. LDAP server restarts)? How can we detect if the connection is dead?
#   * We open a new connection each time a valid username tries to login: could
#     we reuse the same connection?
#
# FIXME: we assume user DN is formatted as follow: uid=$username,$user_base.
# Should we make it configurable?

class LDAPAuthMethod(AuthMethod):
    def __init__(self):
        try:
            import ldap
        except ImportError:
            print(
                "could not import 'ldap', this is necessary for LDAP "
                "authentication; please install python-ldap or change "
                "'auth-method=ldap' in the configuration file.",
                file=sys.stderr)
            sys.exit(1)

        self.ldap = ldap
        self.server = cfg('meta.sr.ht::auth::ldap', 'server')
        self.user_base = cfg('meta.sr.ht::auth::ldap', 'user-base')
        self.create_users = cfgb('meta.sr.ht::auth::ldap', 'create-users')

        bind_dn = cfg('meta.sr.ht::auth::ldap', 'bind-dn')
        bind_pw = cfg('meta.sr.ht::auth::ldap', 'bind-password')

        # Initialize connection to LDAP server.
        try:
            self.conn = ldap.initialize(self.server)
            self.conn.protocol_version = ldap.VERSION3
            self.conn.simple_bind_s(bind_dn, bind_pw)
        except Exception as e:
            print("Could not query LDAP server: {}".format(e))

    def get_dn_for(self, username: str) -> str:
        return "uid={},{}".format(username, self.user_base)

    def ldap_get_user(self, username: str) -> tuple:
        try:
            ldap_search_filter = "uid={}".format(username)
            import_attributes = ['uid', 'mail']
            ldap_match = self.conn.search_s(
                    self.user_base,
                    self.ldap.SCOPE_SUBTREE,
                    ldap_search_filter,
                    import_attributes)

            if len(ldap_match) != 1:
                # Either no match or multiple ones - we don't want to deal with
                # this result.
                return None
            else:
                (dn, ldap_entry) = ldap_match[0]
                uid = ldap_entry['uid'][0].decode("utf-8").lower()
                mail = ldap_entry['mail'][0].decode("utf-8").strip()
                return (uid, mail)

        except Exception as e:
            print("Something went wrong during user LDAP lookup: {}".format(e))
            return None

    def user_valid(self, valid: Validation, username: str, password: str) \
            -> bool:
        user = get_user(username)

        if user is None:
            ldap_match = self.ldap_get_user(username)

            # Not user matching this username in database.
            if not ldap_match:
                valid.error('Username or password incorrect')
                return False

            # Since users will get auto-created here (in prepare_user), validate
            # the username and emails to ensure valid entries in the database.
            (uid, email) = ldap_match
            valid_dummy = Validation({})

            validate_username(valid_dummy, username)
            validate_email(valid_dummy, email)

            if not valid_dummy.ok:
                valid.error('Username or password incorrect')
                return False

            if not self.create_users:
                valid.error('Username or password incorrect')
                return False
        else:
            # Make sure we're using the actual user name for LDAP authentication,
            # even when the user logs in with the email address
            username = user.username


        # Query LDAP server.
        try:
            user_conn = self.ldap.initialize(self.server)
            user_conn.protocol_version = self.ldap.VERSION3
            user_conn.simple_bind_s(self.get_dn_for(username), password)
            user_conn.unbind()
        except self.ldap.INVALID_CREDENTIALS:
            valid.error('Username or password incorrect')
            return False
        except Exception as e:
            valid.error('Something went wrong while querying the'
                    'authentication backend. Please try again later or contact'
                    'your administrator.')
            return False

        return True

    def prepare_user(self, username: str) -> User:
        user = get_user(username)

        if user is None:
            assert self.create_users, ("tried to call prepare_user for an user"
            "that doesn't exist, and create_users is false")

            ldap_match = self.ldap_get_user(username)
            (uid, email) = ldap_match
            user = self.create(username, email)

        return user

    def create(self, username: str, email: str) -> User:
        user = User(username)
        user.email = email
        user.password = ''
        user.invites = cfg("meta.sr.ht::settings", "user-invites", default=0)

        user.confirmation_hash = None
        user.user_type = UserType.active_non_paying

        db.session.add(user)
        db.session.commit()

        audit_log("account created", user=user)

        return user

    def set_user_email(self, user: User, email: str) -> bool:
        ldif = [(self.ldap.MOD_REPLACE, 'mail', str.encode(email))]
        self.conn.modify_s(self.get_dn_for(user.username), ldif)

        user.email = email
        db.session.commit()

    def set_user_password(self, user: User, password: str) -> bool:
        audit_log("password reset", user=user)
        self.conn.passwd_s(self.get_dn_for(user.username), None, password)
