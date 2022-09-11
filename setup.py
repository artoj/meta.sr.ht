#!/usr/bin/env python3
import importlib.resources
import os
import subprocess
import sys

from setuptools import setup

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
      'metasrht.auth',
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
      'dnspython',
      'qrcode',
      'redis',
      'srht',
      'sshpubkeys',
      'stripe',
      'prometheus_client',
      'weasyprint',
      'zxcvbn'
  ],
  extras_require = {
      'unix-pam-auth': ['python_pam'],
  },
  license = 'AGPL-3.0',
  package_data={
      'metasrht': [
          'templates/*.html',
          'static/*',
          'static/icons/*',
          'emails/*',
          'schema.graphqls',
          'default_query.graphql',
      ]
  },
  scripts = [
      'metasrht-daily',
      'metasrht-initdb',
      'metasrht-manageuser',
      'metasrht-migrate',
  ]
)
