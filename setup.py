#!/usr/bin/env python3
from distutils.core import setup
import subprocess
import glob

subprocess.call(["make"])

setup(
  name = 'metasrht',
  packages = [
      'metsrht',
      'metsrht.types',
      'metsrht.blueprints',
  ],
  version = subprocess.run(['git', 'describe', '--tags'],
      stdout=subprocess.PIPE).stdout.decode().strip(),
  description = 'meta.sr.ht website',
  author = 'Drew DeVault',
  author_email = 'sir@cmpwn.com',
  url = 'https://git.sr.ht/~sircmpwn/meta.sr.ht',
  requires = ['srht'],
  license = 'GPL-2.0',
  package_data={
      'metasrht': [
          'templates/*.html',
          'static/*',
      ]
  }
)
