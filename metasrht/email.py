import os
import srht.email
import html.parser
import pystache
from srht.config import cfg, cfgi
from flask_login import current_user

protocol = cfg("server", "protocol")
domain = cfg("server", "domain")
owner_name = cfg("meta.sr.ht", "owner-name")
site_name = cfg("sr.ht", "site-name")

def send_email(template, *args, encrypt_key=None, **kwargs):
    with open(os.path.join(os.path.dirname(__file__), "emails", template)) as f:
        body = html.parser.HTMLParser().unescape(\
            pystache.render(f.read(), {
                'owner-name': owner_name,
                'site-name': site_name,
                'user': current_user,
                'root': '{}://{}'.format(protocol, domain),
                **kwargs
            }))
    srht.email.send_email(body, *args, encrypt_key=encrypt_key)
