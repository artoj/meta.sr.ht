from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.message import Message
from flask_login import current_user
from flask import url_for
from srht.config import cfg, cfgi
import html.parser
import smtplib
import pystache
import pgpy
import os

# TODO: move this into celery worker

site_key, _ = pgpy.PGPKey.from_file(cfg("sr.ht", "pgp-privkey"))

def _url_for(ep, **kw):
    return cfg("server", "protocol") \
        + cfg("server", "domain") \
        + url_for(ep, **kw)

def send_email(template, to, subject, encrypt_key=None, **kwargs):
    if cfg("mail", "smtp-host") == "":
        return
    smtp = smtplib.SMTP(cfg("mail", "smtp-host"), cfgi("mail", "smtp-port"))
    smtp.ehlo()
    smtp.starttls()
    smtp.login(cfg("mail", "smtp-user"), cfg("mail", "smtp-password"))
    with open("emails/" + template) as f:
        message = html.parser.HTMLParser().unescape(\
            pystache.render(f.read(), {
                'owner-name': cfg('sr.ht', 'owner-name'),
                'site-name': cfg('sr.ht', 'site-name'),
                'user': current_user,
                'root': '{}://{}'.format(
                    cfg('server', 'protocol'), cfg('server', 'domain')),
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
        multipart['From'] = cfg("mail", "smtp-user")
        multipart['To'] = to
        smtp.sendmail(cfg("mail", "smtp-user"), [to], multipart.as_string(unixfrom=True))
    else:
        pubkey, _ = pgpy.PGPKey.from_blob(encrypt_key.replace('\r', '').encode())
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
        wrapped['From'] = cfg("mail", "smtp-user")
        wrapped['To'] = to
        smtp.sendmail(cfg("mail", "smtp-user"), [to], wrapped.as_string(unixfrom=True))
    smtp.quit()
