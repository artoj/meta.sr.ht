from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.message import Message
from flask_login import current_user
from meta.config import _cfg, _cfgi
from flask import url_for
import html.parser
import smtplib
import pystache
import pgpy
import os

# TODO: move this into celery worker

site_key, _ = pgpy.PGPKey.from_file(_cfg("sr.ht", "pgp-privkey"))

def _url_for(ep, **kw):
    return _cfg("server", "protocol") \
        + _cfg("server", "domain") \
        + url_for(ep, **kw)

def send_email(template, to, subject, encrypt_key=None, **kwargs):
    if _cfg("mail", "smtp-host") == "":
        return
    smtp = smtplib.SMTP(_cfg("mail", "smtp-host"), _cfgi("mail", "smtp-port"))
    smtp.ehlo()
    smtp.starttls()
    smtp.login(_cfg("mail", "smtp-user"), _cfg("mail", "smtp-password"))
    with open("emails/" + template) as f:
        message = html.parser.HTMLParser().unescape(\
            pystache.render(f.read(), {
                'owner-name': _cfg('sr.ht', 'owner-name'),
                'site-name': _cfg('sr.ht', 'site-name'),
                'user': current_user,
                'root': '{}://{}'.format(
                    _cfg('server', 'protocol'), _cfg('server', 'domain')),
                **kwargs
            }))
    multipart = MIMEMultipart(_subtype="signed", micalg="pgp-sha1",
        protocol="application/pgp-signature")
    text_part = MIMEText(message)
    signature = str(site_key.sign(text_part.as_string().replace('\n', '\r\n')))
    sig_part = Message()
    sig_part['Content-Type'] = 'application/pgp-signature; name="signature.asc"'
    sig_part['Content-Description'] = 'OpenPGP digital signature'
    sig_part.set_payload(signature)
    multipart.attach(text_part)
    multipart.attach(sig_part)
    if not encrypt_key:
        multipart['Subject'] = subject
        multipart['From'] = _cfg("mail", "smtp-user")
        multipart['To'] = to
        smtp.sendmail(_cfg("mail", "smtp-user"), [to], multipart.as_string(unixfrom=True))
    else:
        pubkey, _ = pgpy.PGPKey.from_blob(encrypt_key.replace('\r', '').encode('utf-8'))
        pgp_msg = pgpy.PGPMessage.new(multipart.as_string(unixfrom=True))
        encrypted = str(pubkey.encrypt(pgp_msg))
        ver_part = Message()
        ver_part['Content-Type'] = 'application/pgp-encrypted'
        ver_part.set_payload("Version: 1")
        enc_part = Message()
        enc_part['Content-Type'] = 'application/octet-stream; name="message.asc"'
        enc_part['Content-Description'] = 'OpenPGP encrypted message'
        enc_part.set_payload(encrypted)
        wrapped = MIMEMultipart(_subtype="encrypted", protocol="application/pgp-encrypted")
        wrapped.attach(ver_part)
        wrapped.attach(enc_part)
        wrapped['Subject'] = subject
        wrapped['From'] = _cfg("mail", "smtp-user")
        wrapped['To'] = to
        smtp.sendmail(_cfg("mail", "smtp-user"), [to], wrapped.as_string(unixfrom=True))
    smtp.quit()
