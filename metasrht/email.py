import html
import os
import srht.email
from srht.config import cfg, cfgi
from srht.oauth import current_user
from string import Template

origin = cfg("meta.sr.ht", "origin")
owner_name = cfg("sr.ht", "owner-name")
owner_email = cfg("sr.ht", "owner-email")
site_name = cfg("sr.ht", "site-name")

def send_email(template, *args, encrypt_key=None, headers={}, user=None, **kwargs):
    if user is None:
        user = current_user
    with open(os.path.join(os.path.dirname(__file__), "emails", template)) as f:
        tmpl = Template(f.read())
        body = tmpl.substitute(**{
                'owner_name': owner_name,
                'owner_email': owner_email,
                'site_name': site_name,
                'username': user.username,
                'user_email': user.email,
                'root': origin,
                **kwargs
            })
    srht.email.send_email(body, *args, encrypt_key=encrypt_key, **headers)
