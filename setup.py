#!/usr/bin/env python3
from distutils.core import setup
import subprocess
import glob
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
  ],
  version = ver,
  description = 'meta.sr.ht website',
  author = 'Drew DeVault',
  author_email = 'sir@cmpwn.com',
  url = 'https://git.sr.ht/~sircmpwn/meta.sr.ht',
  install_requires = ['srht', 'pgpy', 'sshpubkeys', 'flask-login', 'pystache'],
  license = 'GPL-2.0',
  package_data={
      'metasrht': [
          'templates/*.html',
          'static/*'
      ]
  }
)
