#!/usr/bin/env python3
from setuptools import setup
import subprocess
import os
import sys
import importlib.resources

with importlib.resources.path('srht', 'Makefile') as f:
    srht_path = f.parent.as_posix()

make = os.environ.get("MAKE") or "make"
subp = subprocess.run([make, "SRHT_PATH=" + srht_path])
if subp.returncode != 0:
    sys.exit(subp.returncode)

ver = os.environ.get("PKGVER") or subprocess.run(['git', 'describe', '--tags'],
      stdout=subprocess.PIPE).stdout.decode().strip()

setup(
  name = 'metasrht',
  packages = [
      'metasrht',
      'metasrht.types',
      'metasrht.blueprints',
      'metasrht.blueprints.api',
      'metasrht.alembic',
      'metasrht.alembic.versions'
  ],
  version = ver,
  description = 'meta.sr.ht website',
  author = 'Drew DeVault',
  author_email = 'sir@cmpwn.com',
  url = 'https://git.sr.ht/~sircmpwn/meta.sr.ht',
  install_requires = [
      'alembic',
      'bcrypt',
      'pgpy',
      'pystache',
      'qrcode',
      'redis',
      'srht',
      'sshpubkeys',
      'stripe',
      'prometheus_client',
      'weasyprint',
      'zxcvbn'
  ],
  license = 'AGPL-3.0',
  package_data={
      'metasrht': [
          'templates/*.html',
          'static/*',
          'static/icons/*',
          'emails/*'
      ]
  },
  scripts = [
      'metasrht-createuser',
      'metasrht-daily',
      'metasrht-initdb',
      'metasrht-invoicestats',
      'metasrht-migrate',
  ]
)
