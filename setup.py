try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

config = {
    'name': 'PyKI',
    'version': '1.0',
    'description': 'TLS PKI manager',
    'author': 'Maibach Alain',
    'author_email': 'alain.maibach@gmail.com',
    'maintainer': 'Maibach Alain',
    'url': 'https://github.com/pykiki',
    'download_url': 'https://github.com/pykiki/PyKI',
    'packages': ['PyKI'],
    'license': 'GNU GPLv3',
    'install_requires': [
        'cffi',
        'cryptography',
        'idna',
        'pyasn1',
        'pycparser',
        'pycrypto',
        'pyOpenSSL',
        'pytz',
        'six',
        'xkcdpass'],
    'platforms': [
        'Linux',
        'OSX'],
    'zip_safe': False,
    'classifiers': [
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.5',
        'Topic :: Utilities']}

setup(**config)
