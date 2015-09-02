#!/usr/bin/env python

"""Distribution Utilities setup program for NDG Security Package

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "24/04/06"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

# Bootstrap setuptools if necessary.
try:
    from setuptools import setup, find_packages
except ImportError:
    from ez_setup import use_setuptools
    use_setuptools()
    from setuptools import setup, find_packages

import sys
import os

# Packages needed for NDG Security
# Note commented out ones fail with PyPI - use explicit link instead
_PKG_DEPENDENCIES = [
    'ndg-httpsclient',
    'ndg_saml',
    'ndg_xacml'
    ]

# Python 2.5 includes ElementTree by default
if sys.version_info[0:2] < (2, 5):
    _PKG_DEPENDENCIES += ['ElementTree', 'cElementTree']

THIS_DIR = os.path.dirname(__file__)
try:
    LONG_DESCR = open(os.path.join(THIS_DIR, 'README.rst')).read()
except IOError:
    LONG_DESCR = """\
NDG Security package for components common to client and server side 
==================================================================== 
NDG Security is the security system originally developed for the UK Natural 
Environment Research Council funded NERC DataGrid.  It's a system to provide
federated access control and identity management and has been applied for use
with the Earth System Grid Federation.
"""

setup(
    name =           		'ndg_security_common',
    version =        		'2.6.0',
    description =           'NERC DataGrid Security package containing common '
                            'utilities used by both server and client '
                            'packages',
    long_description =		LONG_DESCR,
    author =         		'Philip Kershaw',
    author_email =   		'Philip.Kershaw@stfc.ac.uk',
    maintainer =         	'Philip Kershaw',
    maintainer_email =   	'Philip.Kershaw@stfc.ac.uk',
    url =            		'https://github.com/cedadev/ndg_security_common',
    license =               'BSD - See LICENCE file for details',
    install_requires =		_PKG_DEPENDENCIES,
    extras_require = {
        # M2Crypto is required for SSL Client based validation of OpenID
        # Providers
        'openid_relying_party_provider_validation':  ["M2Crypto"],
    },
    dependency_links =		["http://dist.ceda.ac.uk/pip/"],
    packages =       		find_packages(),
    namespace_packages =	['ndg', 'ndg.security'],
    entry_points =         None,
    test_suite =		   'ndg.security.common.test',
    zip_safe =             False
)
