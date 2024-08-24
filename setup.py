#Gets setuptools
from setuptools import setup
# Normal setup.py starts here
import sys, os

version = '0.5'

setup(name='pyscanlogd3',
      version=version,
      description="pyscanlogd3 is a port scan detection tool written in Python3",
      long_description="""\
Pyscanlogd is a port scan detection tool written in pure Python. It can
detect most fast port scans and even can detect port-scans of longer
duration upto an hour. It can run as a daemon as well as in the foreground.
""",
      # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      classifiers=[
          'Development Status :: 5 - Stable',
          'Environment :: Console',
          'Environment :: Desktop Environment',
          'Intended Audience :: End Users/Desktop',
          'License :: New BSD License',
          'Operating System :: OS Independent',
          'Programming Language :: Python3',
          ],
      keywords='networking security python reconnaissance scanning tools',
      author='pythonhacker',
      author_email='abpillai@gmail.com',
      maintainer='pythonhacker',
      maintainer_email='abpillai@gmail.com',
      url='https://github.com/pythonhacker/pyscanlogd3',
      license='BSD3',
      include_package_data = True,    # include everything in source control
      py_modules = ['scanlogger','timerlist','entry','utils','hasher','constants'],
      zip_safe=False,
      entry_points="""
      [console_scripts]
        pyscanlogd3 = scanlogger:main
      """,
      install_requires = [
          'setuptools',
          'dpkt',
          'pypcap']
      )

