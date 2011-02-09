"""Extend M2Crypto SSL functionality for cert verification and custom
timeout settings.

NERC DataGrid Project"""
__author__ = "P J Kershaw"
__date__ = "02/07/07"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
log = logging.getLogger(__name__)

import os
import re

from M2Crypto import SSL, X509
from M2Crypto.httpslib import HTTPSConnection as _HTTPSConnection

from ndg.security.common.X509 import X509Cert, X509Stack, X500DN


class InvalidCertSignature(SSL.Checker.SSLVerificationError):
    """Raise if verification against CA cert public key fails"""


class InvalidCertDN(SSL.Checker.SSLVerificationError):
    """Raise if verification against a list acceptable DNs fails"""
   

class HostCheck(SSL.Checker.Checker, object):
    """Override SSL.Checker.Checker to enable alternate Common Name
    setting match for peer cert"""

    def __init__(self, 
                 peerCertDN=None, 
                 peerCertCN=None,
                 acceptedDNs=None, 
                 caCertList=None,
                 caCertFilePathList=None, 
                 **kw):
        """Override parent class __init__ to enable setting of myProxyServerDN
        setting
        
        @type peerCertDN: string/list
        @param peerCertDN: Set the expected Distinguished Name of the
        server to avoid errors matching hostnames.  This is useful
        where the hostname is not fully qualified.  

        *param acceptedDNs: a list of acceptable DNs.  This enables validation 
        where the expected DN is where against a limited list of certs.
        
        @type peerCertCN: string
        @param peerCertCN: enable alternate Common Name to peer
        hostname
        
        @type caCertList: list type of M2Crypto.X509.X509 types
        @param caCertList: CA X.509 certificates - if set the peer cert's 
        CA signature is verified against one of these.  At least one must
        verify
        
        @type caCertFilePathList: list string types
        @param caCertFilePathList: same as caCertList except input as list
        of CA cert file paths"""
        
        if acceptedDNs is None:
            acceptedDNs = []
            
        if caCertList is None:
            caCertList = []
            
        if caCertFilePathList is None:
            caCertFilePathList = []
        
        SSL.Checker.Checker.__init__(self, **kw)
        
        self.peerCertDN = peerCertDN
        self.peerCertCN = peerCertCN
        self.acceptedDNs = acceptedDNs
        
        if caCertList:
            self.caCertList = caCertList
        elif caCertFilePathList:
            self.caCertFilePathList = caCertFilePathList
        else:
            # Set default to enable len() test in __call__
            self.__caCertStack = ()
            
    def __call__(self, peerCert, host=None):
        """Carry out checks on server ID
        @param peerCert: MyProxy server host certificate as M2Crypto.X509.X509
        instance
        @param host: name of host to check
        """
        if peerCert is None:
            raise SSL.Checker.NoCertificate('SSL Peer did not return '
                                            'certificate')

        peerCertDN = '/'+peerCert.get_subject().as_text().replace(', ', '/')
        try:
            SSL.Checker.Checker.__call__(self, peerCert, host=self.peerCertCN)
            
        except SSL.Checker.WrongHost, e:
            # Try match against peerCertDN set   
            if peerCertDN != self.peerCertDN:
                raise e

        # At least one match should be found in the list - first convert to
        # NDG X500DN type to allow per field matching for DN comparison
        peerCertX500DN = X500DN(dn=peerCertDN)
        
        if self.acceptedDNs:
           matchFound = False
           for dn in self.acceptedDNs:
               x500dn = X500DN(dn=dn)
               if x500dn == peerCertX500DN:
                   matchFound = True
                   break
               
           if not matchFound:
               raise InvalidCertDN('Peer cert DN "%s" doesn\'t match '
                                   'verification list' % peerCertDN)

        if len(self.__caCertStack) > 0:
            try:
                self.__caCertStack.verifyCertChain(
                           x509Cert2Verify=X509Cert(m2CryptoX509=peerCert))
            except Exception, e:
                raise InvalidCertSignature("Peer certificate verification "
                                           "against CA certificate failed: %s" 
                                           % e)
              
        # They match - drop the exception and return all OK instead          
        return True
      
    def __setCACertList(self, caCertList):
        """Set list of CA certs - peer cert must validate against at least one
        of these"""
        self.__caCertStack = X509Stack()
        for caCert in caCertList:
            self.__caCertStack.push(caCert)

    caCertList = property(fset=__setCACertList,
                          doc="list of CA certificates - the peer certificate "
                              "must validate against one")

    def __setCACertsFromFileList(self, caCertFilePathList):
        '''Read CA certificates from file and add them to the X.509
        stack
        
        @type caCertFilePathList: basestring, list or tuple
        @param caCertFilePathList: list of file paths for CA certificates to
        be used to verify certificate used to sign message.  If a single 
        string item is input then this is converted into a tuple
        '''
        if isinstance(caCertFilePathList, basestring):
            caCertFilePathList = (caCertFilePathList,)
            
        elif not isinstance(caCertFilePathList, (list, tuple)):
            raise TypeError('Expecting a basestring, list or tuple type for '
                            '"caCertFilePathList"')

        self.__caCertStack = X509Stack()

        for caCertFilePath in caCertFilePathList:
            self.__caCertStack.push(X509.load_cert(caCertFilePath))
        
    caCertFilePathList = property(fset=__setCACertsFromFileList,
                                  doc="list of CA certificate file paths - "
                                      "peer certificate must validate against "
                                      "one")


class HTTPSConnection(_HTTPSConnection):
    """Modified version of M2Crypto equivalent to enable custom checks with
    the peer and timeout settings
    
    @type defReadTimeout: M2Crypto.SSL.timeout
    @cvar defReadTimeout: default timeout for read operations
    @type defWriteTimeout: M2Crypto.SSL.timeout
    @cvar defWriteTimeout: default timeout for write operations"""    
    defReadTimeout = SSL.timeout(sec=20.)
    defWriteTimeout = SSL.timeout(sec=20.)
    
    def __init__(self, *args, **kw):
        '''Overload to enable setting of post connection check
        callback to SSL.Connection
        
        type *args: tuple
        param *args: args which apply to M2Crypto.httpslib.HTTPSConnection
        type **kw: dict
        param **kw: additional keywords
        @type postConnectionCheck: SSL.Checker.Checker derivative
        @keyword postConnectionCheck: set class for checking peer
        @type readTimeout: M2Crypto.SSL.timeout
        @keyword readTimeout: readTimeout - set timeout for read
        @type writeTimeout: M2Crypto.SSL.timeout
        @keyword writeTimeout: similar to read timeout'''
        
        self._postConnectionCheck = kw.pop('postConnectionCheck',
                                           SSL.Checker.Checker)
        
        if 'readTimeout' in kw:
            if not isinstance(kw['readTimeout'], SSL.timeout):
                raise AttributeError("readTimeout must be of type "
                                     "M2Crypto.SSL.timeout")
            self.readTimeout = kw.pop('readTimeout')
        else:
            self.readTimeout = HTTPSConnection.defReadTimeout
              
        if 'writeTimeout' in kw:
            if not isinstance(kw['writeTimeout'], SSL.timeout):
                raise AttributeError("writeTimeout must be of type "
                                     "M2Crypto.SSL.timeout") 
            self.writeTimeout = kw.pop('writeTimeout')
        else:
            self.writeTimeout = HTTPSConnection.defWriteTimeout
    
        self._clntCertFilePath = kw.pop('clntCertFilePath', None)
        self._clntPriKeyFilePath = kw.pop('clntPriKeyFilePath', None)
        
        _HTTPSConnection.__init__(self, *args, **kw)
        
        # load up certificate stuff
        if (self._clntCertFilePath is not None and 
            self._clntPriKeyFilePath is not None):
            self.ssl_ctx.load_cert(self._clntCertFilePath, 
                                   self._clntPriKeyFilePath)
        
        
    def connect(self):
        '''Overload M2Crypto.httpslib.HTTPSConnection to enable
        custom post connection check of peer certificate and socket timeout'''

        self.sock = SSL.Connection(self.ssl_ctx)
        self.sock.set_post_connection_check_callback(self._postConnectionCheck)

        self.sock.set_socket_read_timeout(self.readTimeout)
        self.sock.set_socket_write_timeout(self.writeTimeout)

        self.sock.connect((self.host, self.port))

    def putrequest(self, method, url, **kw):
        '''Overload to work around bug with unicode type URL'''
        url = str(url)
        _HTTPSConnection.putrequest(self, method, url, **kw) 
         
              
class SSLContextProxy(object):
    """Holder for M2Crypto.SSL.Context parameters"""
    PRE_VERIFY_FAIL, PRE_VERIFY_OK = range(2)
    
    SSL_CERT_FILEPATH_OPTNAME = "sslCertFilePath"
    SSL_PRIKEY_FILEPATH_OPTNAME = "sslPriKeyFilePath"
    SSL_PRIKEY_PWD_OPTNAME = "sslPriKeyPwd"
    SSL_CACERT_FILEPATH_OPTNAME = "sslCACertFilePath"
    SSL_CACERT_DIRPATH_OPTNAME = "sslCACertDir"
    SSL_VALID_DNS_OPTNAME = "sslValidDNs"
    
    OPTNAMES = (
        SSL_CERT_FILEPATH_OPTNAME,
        SSL_PRIKEY_FILEPATH_OPTNAME,
        SSL_PRIKEY_PWD_OPTNAME,
        SSL_CACERT_FILEPATH_OPTNAME,
        SSL_CACERT_DIRPATH_OPTNAME,
        SSL_VALID_DNS_OPTNAME
    )
    
    __slots__ = tuple(["__%s" % name for name in OPTNAMES])
    del name
    
    VALID_DNS_PAT = re.compile(',\s*')
    
    def __init__(self):
        self.__sslCertFilePath = None
        self.__sslPriKeyFilePath = None
        self.__sslPriKeyPwd = None
        self.__sslCACertFilePath = None
        self.__sslCACertDir = None
        self.__sslValidDNs = []

    def createCtx(self, depth=9, **kw):
        """Create an M2Crypto SSL Context from this objects properties
        @type depth: int
        @param depth: max. depth of certificate to verify against
        @type kw: dict
        @param kw: M2Crypto.SSL.Context keyword arguments
        @rtype: M2Crypto.SSL.Context
        @return M2Crypto SSL context object
        """
        ctx = SSL.Context(**kw)
        
        # Configure context according to this proxy's attributes
        if self.sslCertFilePath and self.sslPriKeyFilePath:
            # Pass client certificate
            ctx.load_cert(self.sslCertFilePath, 
                          self.__sslPriKeyFilePath, 
                          lambda *arg, **kw: self.sslPriKeyPwd)
            log.debug("Set client certificate and key in SSL Context")
        else:
            log.debug("No client certificate or key set in SSL Context")
            
        if self.sslCACertFilePath or self.sslCACertDir:
            # Set CA certificates in order to verify peer
            ctx.load_verify_locations(self.sslCACertFilePath, 
                                      self.sslCACertDir)
            mode = SSL.verify_peer|SSL.verify_fail_if_no_peer_cert
        else:
            mode = SSL.verify_fail_if_no_peer_cert
            log.warning('No CA certificate files set: mode set to '
                        '"verify_fail_if_no_peer_cert" only')
            
        if len(self.sslValidDNs) > 0:
            # Set custom callback in order to verify peer certificate DN 
            # against whitelist
            callback = self.createVerifySSLPeerCertCallback()
            log.debug('Set peer certificate Distinguished Name check set in '
                      'SSL Context')
        else:
            callback = None
            log.warning('No peer certificate Distinguished Name check set in '
                        'SSL Context')
            
        ctx.set_verify(mode, depth, callback=callback)
           
        return ctx
 
    def copy(self, sslCtxProxy):
        """Copy settings from another context object
        """
        if not isinstance(sslCtxProxy, SSLContextProxy):
            raise TypeError('Expecting %r for copy method input object; '
                            'got %r' % (SSLContextProxy, type(sslCtxProxy)))
        
        for name in SSLContextProxy.OPTNAMES:
            setattr(self, name, getattr(sslCtxProxy, name))
            
    def createVerifySSLPeerCertCallback(self):
        """Create a callback function to enable the DN of the peer in an SSL
        connection to be verified against a whitelist.  
        
        Nb. Making this function within the scope of a method of the class to
        enables to access instance variables
        """
        
        def _verifySSLPeerCertCallback(preVerifyOK, x509StoreCtx):
            '''SSL verify callback function used to control the behaviour when 
            the SSL_VERIFY_PEER flag is set.  See:
            
            http://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
            
            This implementation applies verification in order to check the DN
            of the peer certificate against a whitelist
            
            @type preVerifyOK: int
            @param preVerifyOK: If a verification error is found, this 
            parameter will be set to 0
            @type x509StoreCtx: M2Crypto.X509.X509_Store_Context
            @param x509StoreCtx: locate the certificate to be verified and 
            perform additional verification steps as needed
            @rtype: int
            @return: controls the strategy of the further verification process. 
            - If verify_callback returns 0, the verification process is 
            immediately stopped with "verification failed" state. If 
            SSL_VERIFY_PEER is set, a verification failure alert is sent to the
            peer and the TLS/SSL handshake is terminated. 
            - If verify_callback returns 1, the verification process is 
            continued. 
            If verify_callback always returns 1, the TLS/SSL handshake will not
            be terminated with respect to verification failures and the 
            connection 
            will be established. The calling process can however retrieve the 
            error code of the last verification error using 
            SSL_get_verify_result or by maintaining its own error storage 
            managed by verify_callback.
            '''
            if preVerifyOK == 0:
                # Something is wrong with the certificate don't bother 
                # proceeding any further
                log.error("verifyCallback: pre-verify OK flagged an error "
                          "with the peer certificate, returning error state "
                          "to caller ...")
                return preVerifyOK
            
            x509CertChain = x509StoreCtx.get1_chain()
            for cert in x509CertChain:
                x509Cert = X509Cert.fromM2Crypto(cert)
                if x509Cert.dn in self.sslValidDNs:
                    return preVerifyOK
                
                subject = cert.get_subject()
                dn = subject.as_text()
                log.debug("verifyCallback: dn = %r", dn)
                
            # No match found so return fail status
            return SSLContextProxy.PRE_VERIFY_FAIL
        
        return _verifySSLPeerCertCallback

    def _getSSLCertFilePath(self):
        return self.__sslCertFilePath
    
    def _setSSLCertFilePath(self, filePath):
        "Set X.509 cert file path property method"
        
        if isinstance(filePath, basestring):
            filePath = os.path.expandvars(filePath)
            
        elif filePath is not None:
            raise TypeError("X.509 cert. file path must be a valid string")
        
        self.__sslCertFilePath = filePath
                
    sslCertFilePath = property(fset=_setSSLCertFilePath,
                               fget=_getSSLCertFilePath,
                               doc="File path to X.509 cert.")
        
    def _getSSLCACertFilePath(self):
        """Get file path for list of CA cert or certs used to validate SSL 
        connections
        
        @rtype sslCACertFilePath: basestring
        @return sslCACertFilePathList: file path to file containing concatenated
        PEM encoded CA certificates."""
        return self.__sslCACertFilePath
    
    def _setSSLCACertFilePath(self, value):
        """Set CA cert file path
        
        @type sslCACertFilePath: basestring, list, tuple or None
        @param sslCACertFilePath: file path to CA certificate file.  If None
        then the input is quietly ignored."""
        if isinstance(value, basestring):
            self.__sslCACertFilePath = os.path.expandvars(value)
            
        elif value is None:
            self.__sslCACertFilePath = value
            
        else:
            raise TypeError("Input CA Certificate file path must be "
                            "a valid string or None type: %r" % type(value)) 
        
        
    sslCACertFilePath = property(fget=_getSSLCACertFilePath,
                                 fset=_setSSLCACertFilePath,
                                 doc="Path to file containing concatenated PEM "
                                     "encoded CA Certificates - used for "
                                     "verification of peer certs in SSL "
                                     "connection")
       
    def _getSSLCACertDir(self):
        """Get file path for list of CA cert or certs used to validate SSL 
        connections
        
        @rtype sslCACertDir: basestring
        @return sslCACertDirList: directory containing PEM encoded CA 
        certificates."""
        return self.__sslCACertDir
    
    def _setSSLCACertDir(self, value):
        """Set CA cert or certs to validate AC signatures, signatures
        of Attribute Authority SOAP responses and SSL connections where 
        AA SOAP service is run over SSL.
        
        @type sslCACertDir: basestring
        @param sslCACertDir: directory containing CA certificate files.
        """
        if isinstance(value, basestring):
            self.__sslCACertDir = os.path.expandvars(value)
        elif value is None:
            self.__sslCACertDir = value
        else:
            raise TypeError("Input CA Certificate directroy must be "
                            "a valid string or None type: %r" % type(value))      
        
    sslCACertDir = property(fget=_getSSLCACertDir,
                            fset=_setSSLCACertDir,
                            doc="Path to directory containing PEM encoded CA "
                                "Certificates used for verification of peer "
                                "certs in SSL connection.   Files in the "
                                "directory must be named with the form "
                                "<hash>.0 where <hash> can be obtained using "
                                "openssl x509 -in cert -hash -noout or using "
                                "the c_rehash OpenSSL script")
    
    def _getSslValidDNs(self):
        return self.__sslValidDNs

    def _setSslValidDNs(self, value):
        if isinstance(value, basestring):  
            pat = SSLContextProxy.VALID_DNS_PAT
            self.__sslValidDNs = [X500DN.fromString(dn) 
                                  for dn in pat.split(value)]
            
        elif isinstance(value, (tuple, list)):
            self.__sslValidDNs = [X500DN.fromString(dn) for dn in value]
        else:
            raise TypeError('Expecting list/tuple or basestring type for "%s" '
                            'attribute; got %r' %
                            (SSLContextProxy.SSL_VALID_DNS_OPTNAME, 
                             type(value)))
    
    sslValidDNs = property(_getSslValidDNs, 
                           _setSslValidDNs, 
                           doc="whitelist of acceptable certificate "
                               "Distinguished Names for peer certificates in "
                               "SSL requests")

    def _getSSLPriKeyFilePath(self):
        return self.__sslPriKeyFilePath
    
    def _setSSLPriKeyFilePath(self, filePath):
        "Set ssl private key file path property method"
        
        if isinstance(filePath, basestring):
            filePath = os.path.expandvars(filePath)

        elif filePath is not None:
            raise TypeError("Private key file path must be a valid "
                            "string or None type")
        
        self.__sslPriKeyFilePath = filePath
        
    sslPriKeyFilePath = property(fget=_getSSLPriKeyFilePath,
                                 fset=_setSSLPriKeyFilePath,
                                 doc="File path to SSL private key")
 
    def _setSSLPriKeyPwd(self, sslPriKeyPwd):
        "Set method for ssl private key file password"
        if not isinstance(sslPriKeyPwd, (type(None), basestring)):
            raise TypeError("Signing private key password must be None "
                            "or a valid string")
        
        # Explicitly convert to string as M2Crypto OpenSSL wrapper fails with
        # unicode type
        self.__sslPriKeyPwd = str(sslPriKeyPwd)

    def _getSSLPriKeyPwd(self):
        "Get property method for SSL private key"
        return self.__sslPriKeyPwd
        
    sslPriKeyPwd = property(fset=_setSSLPriKeyPwd,
                             fget=_getSSLPriKeyPwd,
                             doc="Password protecting SSL private key file")

    def __getstate__(self):
        '''Enable pickling for use with beaker.session'''
        _dict = {}
        for attrName in SSLContextProxy.__slots__:
            # Ugly hack to allow for derived classes setting private member
            # variables
            if attrName.startswith('__'):
                attrName = "_SSLContextProxy" + attrName
                
            _dict[attrName] = getattr(self, attrName)
            
        return _dict
        
    def __setstate__(self, attrDict):
        '''Enable pickling for use with beaker.session'''
        for attr, val in attrDict.items():
            setattr(self, attr, val)