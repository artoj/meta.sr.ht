import html
import os
import pystache
import srht.email
from srht.config import cfg, cfgi
from srht.oauth import current_user

origin = cfg("meta.sr.ht", "origin")
owner_name = cfg("sr.ht", "owner-name")
owner_email = cfg("sr.ht", "owner-email")
site_name = cfg("sr.ht", "site-name")

def send_email(template, *args, encrypt_key=None, headers={}, **kwargs):
    with open(os.path.join(os.path.dirname(__file__), "emails", template)) as f:
        body = html.unescape(
            pystache.render(f.read(), {
                'owner-name': owner_name,
                'owner-email': owner_email,
                'site-name': site_name,
                'user': current_user,
                'root': origin,
                **kwargs
            }))
    srht.email.send_email(body, *args, encrypt_key=encrypt_key, **headers)
