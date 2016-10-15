import smtplib
import pystache
import html.parser
import os

from email.mime.text import MIMEText
from flask import url_for

from meta.config import _cfg, _cfgi

# TODO: move this into celery worker

def _url_for(ep, **kw):
    return _cfg("server", "protocol") \
        + _cfg("server", "domain") \
        + url_for(ep, **kw)

def send_email(template, to, subject, **kwargs):
    if _cfg("mail", "smtp-host") == "":
        return
    smtp = smtplib.SMTP(_cfg("mail", "smtp-host"), _cfgi("mail", "smtp-port"))
    smtp.ehlo()
    smtp.starttls()
    smtp.login(_cfg("mail", "smtp-user"), _cfg("mail", "smtp-password"))
    with open("emails/" + template) as f:
        message = MIMEText(html.parser.HTMLParser().unescape(\
            pystache.render(f.read(), {
                'owner-name': _cfg('sr.ht', 'owner-name'),
                'site-name': _cfg('sr.ht', 'site-name'),
                'root': '{}://{}'.format(
                    _cfg('server', 'protocol'), _cfg('server', 'domain')),
                **kwargs
            })))
    message['Subject'] = subject
    message['From'] = _cfg("mail", "smtp-user")
    message['To'] = to
    smtp.sendmail(_cfg("mail", "smtp-user"), [to], message.as_string())
    smtp.quit()
