#!/usr/bin/env python3
from setuptools import setup
import subprocess
import os

subprocess.call(["make"])

ver = os.environ.get("PKGVER") or subprocess.run(['git', 'describe', '--tags'],
      stdout=subprocess.PIPE).stdout.decode().strip()

setup(
  name = 'metasrht',
  packages = [
      'metasrht',
      'metasrht.types',
      'metasrht.blueprints',
      'metasrht.alembic',
      'metasrht.alembic.versions'
  ],
  version = ver,
  description = 'meta.sr.ht website',
  author = 'Drew DeVault',
  author_email = 'sir@cmpwn.com',
  url = 'https://git.sr.ht/~sircmpwn/meta.sr.ht',
  install_requires = [
      'srht',
      'pgpy',
      'sshpubkeys',
      'flask-login',
      'pystache',
      'bcrypt',
      'pyotp',
      'qrcode',
      'redis',
  ],
  license = 'AGPL-3.0',
  package_data={
      'metasrht': [
          'templates/*.html',
          'static/*',
          'static/icons/*',
          'emails/*'
      ]
  }
)
