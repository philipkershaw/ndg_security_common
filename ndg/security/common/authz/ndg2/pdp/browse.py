"""NDG Policy Decision Point for NDG Browse - access constraints for a 
resource are determined from MOLES access constraints in the data.  Nb. the
access control portions of the schema are used for CSML also.

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "04/04/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"

import logging
log = logging.getLogger(__name__)

import sys # tracefile config param may be set to e.g. sys.stderr
import urllib2
import socket
from ConfigParser import SafeConfigParser

# For parsing of properties file
from os.path import expandvars as expVars

from ndg.security.common.authz.pdp import PDPInterface, PDPError, \
    PDPUserAccessDenied, PDPUserNotLoggedIn, PDPMissingResourceConstraints, \
    PDPUnknownResourceType, PDPUserInsufficientPrivileges, \
    PDPMissingUserHandleAttr
    
from ndg.security.common.sessionmanager import SessionManagerClient, SessionNotFound,\
    SessionCertTimeError, SessionExpired, InvalidSession, \
    AttributeRequestDenied                   
    
from ndg.security.common.X509 import X500DN               

class InvalidAttributeCertificate(PDPError):
    "The certificate containing authorisation roles is invalid"
    def __init__(self, msg=None):
        PDPError.__init__(self, msg or InvalidAttributeCertificate.__doc__)
    
class SessionExpiredMsg(PDPError):
    'Session has expired.  Please re-login'
    def __init__(self, msg=None):
        PDPError.__init__(self, msg or SessionExpiredMsg.__doc__)

class InvalidSessionMsg(PDPError):
    'Session is invalid.  Please try re-login'
    def __init__(self, msg=None):
        PDPError.__init__(self, msg or InvalidSessionMsg.__doc__)

class InitSessionCtxError(PDPError):
    'A problem occurred initialising a session connection'
    def __init__(self, msg=None):
        PDPError.__init__(self, msg or InitSessionCtxError.__doc__)

class AttributeCertificateRequestError(PDPError):
    'A problem occurred requesting a certificate containing authorisation roles'
    def __init__(self, msg=None):
        PDPError.__init__(self,msg or AttributeCertificateRequestError.__doc__)

class URLCannotBeOpened(PDPError):
    """Raise from canURLBeOpened PullModelHandler class method
    if URL is invalid - this method is used to check the AA
    service"""


class BrowsePDP(PDPInterface):
    """Make access control decision based on a MOLES access constraint 
    (applies to CSML too) and user security token
    
    This class conforms to the PDPInterface and so can be set-up from a PEP
    (Policy Enforcement Point) object"""
    
    molesXMLNS = 'http://ndg.nerc.ac.uk/moles'
    csmlXMLNS = 'http://ndg.nerc.ac.uk/csml'
    
    roleElemName = 'attrauthRole'
    aaElemName = 'dgAttributeAuthority'
    
    molesSimpleConditionPth = \
        '%sdgMetadataSecurity/%sdgSecurityCondition/%ssimpleCondition'
    
    # MOLES B0 query
    b0SimpleConditionXPth = molesSimpleConditionPth % (('{'+molesXMLNS+'}',)*3)

    # MOLES B1 is dynamically generated from B0 and has no schema    
    b1SimpleConditionXPth = molesSimpleConditionPth % (('', )*3)
    
    # CSML Query
    a0SimpleConditionXPth = \
        '{%s}AccessControlPolicy/{%s}dgSecurityCondition/{%s}simpleCondition'%\
        ((csmlXMLNS, )*2 + (molesXMLNS,))

    defParam = {'aaURI': '',
                'sslCACertFilePathList': [],
                'tracefile': None,
                'acCACertFilePathList': [], 
                'acIssuer': '',
                'wssCfgFilePath': None,
                'wssCfgSection': 'DEFAULT'}
            
    
    def __init__(self,
                 cfg=None, 
                 cfgSection='DEFAULT',
                 **cfgKw):
        """Initialise based on settings from a config file, config file object
        or keywords:
        
        @type cfg: string / ConfigParser object
        @param cfg: if a string type, this is interpreted as the file path to
        a configuration file, otherwise it will be treated as a ConfigParser 
        object 
        @type cfgSection: string
        @param cfgSection: sets the section name to retrieve config params 
        from
        @type cfgKw: dict
        @param cfgKw: set parameters as key value pairs."""
        
        self.resrcURI = None
        self.resrcDoc = None
        self.smURI = None
        self.userSessID = None
        self.username = None
        
        # Set from config file
        if isinstance(cfg, basestring):
            self._cfg = SafeConfigParser()
            self._readConfig(cfg)
        else:
            self._cfg = cfg
        
        # Parse settings
        if cfg:
            self._parseConfig(cfgSection)
            
                
        # Separate keywords into PDP and WS-Security specific items
        paramNames = cfgKw.keys()
        for paramName in paramNames:
            if paramName in BrowsePDP.defParam:
                # Keywords are deleted as they are set
                setattr(self, paramName, cfgKw.pop('paramName'))
                
        # Remaining keys must be for WS-Security config
        self.wssCfg = cfgKw    

        
    def _getSecurityConstraints(self):
        '''Query the input document for a security role and Attribute Authority
        URI constraints.  The query structure is dependent on the schema of the
        document
        
        @rtype: tuple
        @return: required role and the URI for the Attribute Authority to 
        query.  If role is None, no security is set'''
        
        if self.resrcURI.schema == 'NDG-B0':
            log.info(\
            'Checking for constraints for MOLES B0 document ...')

            roleXPth = '%s/{%s}%s' % (BrowsePDP.b0SimpleConditionXPth, 
                                      BrowsePDP.molesXMLNS, 
                                      BrowsePDP.roleElemName)
            
            aaXPth = '%s/{%s}%s' % (BrowsePDP.b0SimpleConditionXPth, 
                                    BrowsePDP.molesXMLNS, 
                                    BrowsePDP.aaElemName)
        
        elif self.resrcURI.schema == 'NDG-B1':
            # MOLES B1 is dynamically generated from B0 and has no schema
            log.info(\
            'Checking for constraints for MOLES B1 document ...')

            roleXPth = '%s/%s' % (BrowsePDP.b1SimpleConditionXPth,
                                  BrowsePDP.roleElemName)
            
            aaXPth = '%s/%s' % (BrowsePDP.b1SimpleConditionXPth,
                                BrowsePDP.aaElemName)
        
        elif self.resrcURI.schema == 'NDG-A0':
            log.info(\
                'Checking for constraints for CSML document ...')
        
            roleXPth = '%s/{%s}%s' % (BrowsePDP.a0SimpleConditionXPth, 
                                      BrowsePDP.molesXMLNS, 
                                      BrowsePDP.roleElemName)
            
            aaXPth = '%s/{%s}%s' % (BrowsePDP.a0SimpleConditionXPth, 
                                    BrowsePDP.molesXMLNS, 
                                    BrowsePDP.aaElemName)            
        else:
            log.warning('No access control set for schema type: "%s"' % \
                        self.resrcURI.schema)
            return None, None # no access control
        

        # Execute queries for role and Attribute Authority elements and extract
        # the text.  Default to None if not found
        roleElem = self.resrcDoc.tree.find(roleXPth)        
        if roleElem is not None:
            role = roleElem.text
        else:
            role = None
            
        aaURIElem = self.resrcDoc.tree.find(aaXPth)
        if aaURIElem is not None:
            aaURI = aaURIElem.text
        else:
            aaURI = None

        return role, aaURI

  
    def _readConfig(self, cfgFilePath):
        '''Read PDP configuration file'''
        self._cfg.read(cfgFilePath)


    def _parseConfig(self, section='DEFAULT'):
        '''Extract parameters from _cfg config object'''
        log.debug("BrowsePDP._parseConfig ...")
        
        # Copy directly into attribute of this object
        for paramName, paramVal in BrowsePDP.defParam.items():
            if not self._cfg.has_option(section, paramName): 
                # Set default if parameter is missing
                log.debug("Setting default %s = %s" % (paramName, paramVal))
                setattr(self, paramName, paramVal)
                continue
             
            if paramName.lower() == 'tracefile':
                val = self._cfg.get(section, paramName)
                if val:
                    setattr(self, paramName, eval(val))
                else:
                    setattr(self, paramName, None)
                       
            elif isinstance(paramVal, list):
                listVal = expVars(self._cfg.get(section, paramName)).split()
                setattr(self, paramName, listVal)
            else:
                val = expVars(self._cfg.get(section, paramName))
                setattr(self, paramName, val)            


    def accessPermitted(self, resrcHandle, userHandle, accessType=None):
        """Make an access control decision based on whether the user is
        authenticated and has the required roles
        
        @type resrcHandle: dict
        @param resrcHandle: dict 'uri' = resource URI, 'doc' = 
        ElementTree type doc
        
        @type userHandle: dict
        @param userHandle: dict with keys 'sid' = user session ID,
        'h' = Session Manager URI
        
        @type accessType: -
        @param accessType: not implemented - logs a warning if set
        
        @rtype: bool
        @return: True if access permitted; False if denied or else raise
        an Exception
        
        @type uri: string
        @param uri: URI corresponding to data granule ID
        
        @type: ElementTree Element
        @param securityElement: MOES security constraint containing role and
        Attribute Authority URI. In xml, could look like:
        <moles:effect>allow</moles:effect>
            <moles:simpleCondition>
            <moles:dgAttributeAuthority>http://dev.badc.rl.ac.uk/AttributeAuthority</moles:dgAttributeAuthority>
            <moles:attrauthRole>coapec</moles:attrauthRole>
        </moles:simpleCondition>
        NB: xmlns:moles="http://ndg.nerc.ac.uk/moles"
        
        @type: pylons.session
        @param userHandle: dict-like session object containing security 
        tokens.  Resets equivalent object attribute."""
          
        log.debug("Calling BrowsePDP.accessPermitted ...")
        
        if accessType is not None:
            log.warning("An accessType = [%s] " % accessType + \
                        "was set Browse assumes all access type is based " + \
                        "on the role attribute associated with the data")
                
        # Check that the user is logged in.  - The User handle contains 
        # 'h' = Session Manager URI and 'sid' user Session ID
        try:
            self.smURI = userHandle['h']
            self.userSessID = userHandle['sid']
            self.username = userHandle['u']
            
        except KeyError, e:
            log.error("User handle missing key %s" % e)
            raise PDPMissingUserHandleAttr()
        
        except TypeError, e:
            log.warning("No User handle set - user is not logged in: %s" % e)
            
        # Resource handle contains URI and ElementTree resource security 
        # element
        try:
            self.resrcURI = resrcHandle['uri']
            self.resrcDoc = resrcHandle['doc'] 
            
        except KeyError, e:
            log.error("Resource handle missing key %s" % e)
            raise PDPMissingResourceConstraints()
        
        except TypeError, e:
            log.error("Invalid Resource handle: %s" % e)
            raise PDPMissingResourceConstraints()

        # First query the document for a security constraint
        role, aaURI = self._getSecurityConstraints()
        if not role:
            # No security set
            log.info("No security role constraint found for [%s]" %\
                     self.resrcURI.schema + \
                     " type document [%s]: GRANTING ACCESS for user %s" % \
                     (self.resrcURI, self.username))
            return

        # TODO: OpenID users have no session with the Session Manager
        if not self.userSessID:
            log.error("User [%s] has no session ID allocated " % \
                      self.username + \
                      "for connection to the Session Manager: raising " + \
                      "PDPUserInsufficientPrivileges exception...")            
            raise PDPUserInsufficientPrivileges()
            
        # Sanity check on Attribute Authority URI retrieved from the data
        if aaURI:            
            # Check Attribute Authority address
            try:
                BrowsePDP.urlCanBeOpened(aaURI)
                
            except URLCannotBeOpened, e:
                # Catch situation where either Attribute Authority address in 
                # the data invalid or none was set.  In this situation verify
                # against the Attribute Authority set in the config   
                log.warning('security constraint ' + \
                            'Attribute Authority address is invalid: "%s"' % \
                            e + \
                            ' - defaulting to config file setting: [%s]' % \
                            self.aaURI)
                aaURI = self.aaURI
        else:
            log.warning("Attribute Authority element not " + \
                        "set in MOLES security constraints - defaulting " + \
                        "to config file setting: [%s]" % self.aaURI)
            aaURI = self.aaURI
   
        # Retrieve Attribute Certificate from user's session held by
        # Session Manager
        attCert = self._pullUserSessionAttCert(aaURI, role)
        
        # Check its validity
        self._checkAttCert(attCert)
                   
        log.info('ACCESS GRANTED for user "%s" ' % \
                 attCert.userId + \
                 'to "%s" secured with role "%s" ' % \
                 (self.resrcURI, role) + \
                 'using attribute certificate:\n\n%s' % attCert)
            
        
    def _pullUserSessionAttCert(self, aaURI, role):
        """Check to see if the Session Manager can deliver an Attribute 
        Certificate with the required role to gain access to the resource
        in question
        
        @type aaURI: string
        @param aaURI: address of Attribute Authority that the Session Manager
        will call in order to request an AC on behalf of the user
        
        @type role: string
        @param role: role controlling access to the secured resource"""
        
        if not self.smURI:
            log.error("No Session Manager URI set.")
            raise InitSessionCtxError()
            
        try:
            # Create Session Manager client - if a file path was set, setting
            # are read from a separate config file section otherwise, from the
            # PDP config object
            self.smClnt = SessionManagerClient(uri=self.smURI,
                            sslCACertFilePathList=self.sslCACertFilePathList,
                            tracefile=self.tracefile,
                            cfg=self.wssCfgFilePath or self._cfg,
                            cfgFileSection=self.wssCfgSection,
                            **self.wssCfg)
        except Exception, e:
            log.error("Creating Session Manager client: %s" % e)
            raise InitSessionCtxError()
        
                  
        try:
            # Make request for attribute certificate
            attCert = self.smClnt.getAttCert(attributeAuthorityURI=aaURI,
                                             sessID=self.userSessID,
                                             reqRole=role)
            return attCert
        
        except AttributeRequestDenied, e:
            log.info("Request for attribute certificate denied: %s" % e)
            raise PDPUserAccessDenied()
        
        except SessionNotFound, e:
            log.info("No session found: %s" % e)
            raise PDPUserNotLoggedIn()

        except SessionExpired, e:
            log.info("Session expired: %s" % e)
            raise InvalidSessionMsg()

        except SessionCertTimeError, e:
            log.info("Session cert. time error: %s" % e)
            raise InvalidSessionMsg()
            
        except InvalidSession, e:
            log.info("Invalid user session: %s" % e)
            raise InvalidSessionMsg()

        except Exception, e:
            log.error("Request from Session Manager [%s] " % self.smURI + \
                      "to Attribute Authority [%s] for " % aaURI + \
                      "attribute certificate: %s: %s" % (e.__class__, e))
            raise AttributeCertificateRequestError()
        

    def _checkAttCert(self, attCert):
        '''Check attribute certificate is valid
        
        @type attCert: ndg.security.common.AttCert.AttCert
        @param attCert: attribute certificate to be check for validity'''
        attCert.certFilePathList = self.acCACertFilePathList
        try:
            attCert.isValid(raiseExcep=True)
        except Exception, e:
            log.error("Attribute Certificate: %s" % e)
            raise InvalidAttributeCertificate()  
         
        # Check it's issuer is as expected - Convert to X500DN to do equality 
        # test
        acIssuerDN = X500DN(self.acIssuer)
        if attCert.issuerDN != acIssuerDN:
            log.error('access denied: Attribute Certificate ' + \
                'issuer DN, "%s" ' % attCert.issuerDN + \
                'must match this data provider\'s Attribute Authority ' + \
                'DN: "%s"' % acIssuerDN)
            raise InvalidAttributeCertificate()


    @classmethod
    def urlCanBeOpened(cls, url, timeout=5, raiseExcep=True):
       """Check url can be opened - adapted from 
       http://mail.python.org/pipermail/python-list/2004-October/289601.html
       """
    
       found = False
       defTimeOut = socket.getdefaulttimeout()
       try:
           socket.setdefaulttimeout(timeout)

           try:
               urllib2.urlopen(url)
           except (urllib2.HTTPError, urllib2.URLError,
                   socket.error, socket.sslerror, AttributeError), e:
               if raiseExcep:
                   raise URLCannotBeOpened(str(e))
           
           found = True
         
       finally:
           socket.setdefaulttimeout(defTimeOut)
           
       return found
      
    
def makeDecision(resrcHandle, userHandle, accessType=None, **kw):
    '''One call Wrapper interface to PDP'''
    return BrowsePDP(**kw)(resrcHandle, userHandle)

 
