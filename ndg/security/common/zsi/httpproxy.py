"""Replacement for httplib.HTTPConnection to enable ZSI clients to reach
remote services through a local HTTP Proxy

Adapted from pywebsvcs mailings March/April '08

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "20/05/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import httplib, os
import urlparse

class ProxyHTTPConnection(httplib.HTTPConnection):
    '''Replacement for httplib.HTTPConnection to enable ZSI clients to reach
    remote services through a local HTTP Proxy.
    
    Adapted from pywebsvcs mailings March/April '08'''
    
    def __init__(self, *arg, **kw):
        '''
        @type host: string
        @param host: hostname (+ port) e.g. localhost:8080
        @type httpProxyHost: string
        @param httpProxyHost: hostname of HTTP Proxy defaults to http_proxy
        environment variable
        @type noHttpProxyList: list
        @param    
        '''
        # Pick-up environment variable and strip protocol prefix
        httpProxyHostEnv=os.environ.get('http_proxy', '').replace('http://','')
        httpProxyHost = kw.pop('httpProxyHost', None)
        
        # Check for exclusions
        noHttpProxyList = kw.pop('noHttpProxyList', []) or \
                                    os.environ.get('no_proxy', '').split(',')

        if arg[0] in noHttpProxyList:
            self.connectTo = arg[0]
        else:
            self.connectTo = httpProxyHost or httpProxyHostEnv or arg[0]

        self.targetHost = arg[0]

        httplib.HTTPConnection.__init__(self, self.connectTo, **kw)


    def putrequest(self, method, url, **kw):
        
        if self.connectTo != self.targetHost:
            scheme, netloc, path, nil, nil, nil = urlparse.urlparse(url)
            scheme = scheme or 'http'
            netloc = netloc or self.targetHost
            uri = scheme + '://' + netloc + path
        else :
            uri = url

        httplib.HTTPConnection.putrequest(self, method, uri, **kw)
