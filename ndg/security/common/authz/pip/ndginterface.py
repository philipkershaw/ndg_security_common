"""PIP with interface to the NDG2 Attribute Authority.  This uses a SOAP/WSDL 
based client interface and handles the NDG Attribute Certificate format.

This interface is superceded by the SAML 2.0 based Attribute Query interface
used with ESG.

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "19/02/10"
__copyright__ = "(C) 2010 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
import traceback
import logging
log = logging.getLogger(__name__)

from ndg.security.common.wssecurity import WSSecurityConfig
        
from ndg.security.common.AttCert import (AttCertInvalidSignature, 
    AttCertNotBeforeTimeError, AttCertExpired, AttCertError)
      
from ndg.security.common.sessionmanager import (SessionManagerClient, 
    SessionNotFound, SessionCertTimeError, SessionExpired, InvalidSession, 
    AttributeRequestDenied)

from ndg.security.common.attributeauthority import (AttributeAuthorityClient, 
    NoTrustedHosts, NoMatchingRoleInTrustedHosts, 
    InvalidAttributeAuthorityClientCtx)
from ndg.security.common.attributeauthority import AttributeRequestDenied as \
    AA_AttributeRequestDenied
    
from ndg.security.common.authz import SubjectBase, SubjectRetrievalError 
from ndg.security.common.authz.pip import (PIPAttributeQuery, PIPBase,
                                           PIPAttributeResponse)


class Subject(SubjectBase):
    '''Subject designator'''
    namespaces = SubjectBase.namespaces + (
        "urn:ndg:security:authz:1.0:attr:subject:sessionId",
        "urn:ndg:security:authz:1.0:attr:subject:sessionManagerURI",
    )
    (USERID_NS, ROLES_NS, SESSIONID_NS, SESSIONMANAGERURI_NS) = namespaces

    
class InvalidAttributeCertificate(SubjectRetrievalError):
    "The certificate containing authorisation roles is invalid"
    def __init__(self, msg=None):
        SubjectRetrievalError.__init__(self, msg or 
                                       InvalidAttributeCertificate.__doc__)


class AttributeCertificateInvalidSignature(SubjectRetrievalError):
    ("There is a problem with the signature of the certificate containing "
     "authorisation roles")
    def __init__(self, msg=None):
        SubjectRetrievalError.__init__(self, msg or 
                                AttributeCertificateInvalidSignature.__doc__)

              
class AttributeCertificateNotBeforeTimeError(SubjectRetrievalError):
    ("There is a time issuing error with certificate containing authorisation "
    "roles")
    def __init__(self, msg=None):
        SubjectRetrievalError.__init__(self, msg or 
                                AttributeCertificateNotBeforeTimeError.__doc__)
        
class AttributeCertificateExpired(SubjectRetrievalError):
    "The certificate containing authorisation roles has expired"
    def __init__(self, msg=None):
        SubjectRetrievalError.__init__(self, msg or 
                                       AttributeCertificateExpired.__doc__)

            
class SessionExpiredMsg(SubjectRetrievalError):
    'Session has expired.  Please re-login at your home organisation'
    def __init__(self, msg=None):
        SubjectRetrievalError.__init__(self, msg or SessionExpiredMsg.__doc__)


class SessionNotFoundMsg(SubjectRetrievalError):
    'No session was found.  Please try re-login with your home organisation'
    def __init__(self, msg=None):
        SubjectRetrievalError.__init__(self, msg or 
                                       SessionNotFoundMsg.__doc__)


class InvalidSessionMsg(SubjectRetrievalError):
    'Session is invalid.  Please try re-login with your home organisation'
    def __init__(self, msg=None):
        SubjectRetrievalError.__init__(self, msg or 
                                       InvalidSessionMsg.__doc__)


class InitSessionCtxError(SubjectRetrievalError):
    'A problem occurred initialising a session connection'
    def __init__(self, msg=None):
        SubjectRetrievalError.__init__(self, msg or 
                                       InitSessionCtxError.__doc__)


class AttributeCertificateRequestError(SubjectRetrievalError):
    'A problem occurred requesting a certificate containing authorisation roles'
    def __init__(self, msg=None):
        SubjectRetrievalError.__init__(self, msg or 
                                    AttributeCertificateRequestError.__doc__)
        
class AttributeCertificateRequestDenied(SubjectRetrievalError):
    'The request for a certificate containing authorisation roles was denied'
    def __init__(self, msg=None):
        SubjectRetrievalError.__init__(self, msg or 
                                    AttributeCertificateRequestError.__doc__)
        
         
class PIP(PIPBase):
    """Policy Information Point - this implementation enables the PDP to 
    retrieve attributes about the Subject"""
    wsseSectionName = 'wssecurity'
    
    def __init__(self, prefix='', **cfg):
        '''Set-up WS-Security and SSL settings for connection to an
        Attribute Authority
        
        @type **cfg: dict
        @param **cfg: keywords including 'sslCACertFilePathList' used to set a
        list of CA certificates for an SSL connection to the Attribute
        Authority if used and also WS-Security settings as used by
        ndg.security.common.wssecurity.WSSecurityConfig
        '''
        self.wssecurityCfg = WSSecurityConfig()
        wssePrefix = prefix + PIP.wsseSectionName
        self.wssecurityCfg.update(cfg, prefix=wssePrefix)
                 
        # List of CA certificates used to verify peer certificate with SSL
        # connections to Attribute Authority
        self.sslCACertFilePathList = cfg.get(prefix+'sslCACertFilePathList', [])
        
        # List of CA certificates used to verify the signatures of 
        # Attribute Certificates retrieved
        self.caCertFilePathList = cfg.get(prefix + 'caCertFilePathList', [])

    def attributeQuery(self, attributeQuery):
        """Query the Attribute Authority specified in the request to retrieve
        the attributes if any corresponding to the subject
        
        @type attributeResponse: PIPAttributeQuery
        @param attributeResponse: 
        @rtype: PIPAttributeResponse
        @return: response containing the attributes retrieved from the
        Attribute Authority"""
        
        subject = attributeQuery[PIPAttributeQuery.SUBJECT_NS]
        username = subject[Subject.USERID_NS]
        sessionId = subject[Subject.SESSIONID_NS]
        attributeAuthorityURI = attributeQuery[
                                    PIPAttributeQuery.ATTRIBUTEAUTHORITY_NS]
        
        sessionId = subject[Subject.SESSIONID_NS]
        
        log.debug("PIP: received attribute query: %r", attributeQuery)
        
        attributeCertificate = self._getAttributeCertificate(
                    attributeAuthorityURI,
                    username=username,
                    sessionId=sessionId,
                    sessionManagerURI=subject[Subject.SESSIONMANAGERURI_NS])

        attributeResponse = PIPAttributeResponse()
        attributeResponse[Subject.ROLES_NS] = attributeCertificate.roles
        
        log.debug("PIP.attributeQuery response: %r", attributeResponse)
        
        return attributeResponse
    
    def _getAttributeCertificate(self,
                                 attributeAuthorityURI,
                                 username=None,
                                 sessionId=None,
                                 sessionManagerURI=None):
        '''Retrieve an Attribute Certificate

        @type attributeAuthorityURI: basestring
        @param attributeAuthorityURI: URI to Attribute Authority service
        @type username: basestring
        @param username: subject user identifier - could be an OpenID        
        @type sessionId: basestring
        @param sessionId: Session Manager session handle
        @type sessionManagerURI: basestring
        @param sessionManagerURI: URI to remote session manager service
        @rtype: ndg.security.common.AttCert.AttCert
        @return: Attribute Certificate containing user roles
        '''

        if sessionId and sessionManagerURI:
            attrCert = self._getAttributeCertificateFromSessionManager(
                                                     attributeAuthorityURI,
                                                     sessionId,
                                                     sessionManagerURI)
        else:
            attrCert = self._getAttributeCertificateFromAttributeAuthority(
                                                     attributeAuthorityURI,
                                                     username)
        
        try:
            attrCert.certFilePathList = self.caCertFilePathList
            attrCert.isValid(raiseExcep=True)
        
        except AttCertInvalidSignature, e:
            log.exception(e)
            raise AttributeCertificateInvalidSignature()
        
        except AttCertNotBeforeTimeError, e:   
            log.exception(e)
            raise AttributeCertificateNotBeforeTimeError()
        
        except AttCertExpired, e:   
            log.exception(e)
            raise AttributeCertificateExpired()

        except AttCertError, e:
            log.exception(e)
            raise InvalidAttributeCertificate()
        
        return attrCert
            
    def _getAttributeCertificateFromSessionManager(self,
                                                   attributeAuthorityURI,
                                                   sessionId,
                                                   sessionManagerURI):
        '''Retrieve an Attribute Certificate using the subject's Session
        Manager
        
        @type sessionId: basestring
        @param sessionId: Session Manager session handle
        @type sessionManagerURI: basestring
        @param sessionManagerURI: URI to remote session manager service
        @type attributeAuthorityURI: basestring
        @param attributeAuthorityURI: URI to Attribute Authority service
        @rtype: ndg.security.common.AttCert.AttCert
        @return: Attribute Certificate containing user roles
        '''
        
        log.debug("PIP._getAttributeCertificateFromSessionManager ...")
        
        try:
            # Create Session Manager client - if a file path was set, setting
            # are read from a separate config file section otherwise, from the
            # PDP config object
            smClnt = SessionManagerClient(
                            uri=sessionManagerURI,
                            sslCACertFilePathList=self.sslCACertFilePathList,
                            cfg=self.wssecurityCfg)
        except Exception, e:
            log.error("Creating Session Manager client: %s" % e)
            raise InitSessionCtxError()
             
        try:
            # Make request for attribute certificate
            return smClnt.getAttCert(
                                attributeAuthorityURI=attributeAuthorityURI,
                                sessID=sessionId)
        
        except AttributeRequestDenied, e:
            log.error("Request for attribute certificate denied: %s" % e)
            raise AttributeCertificateRequestDenied()
        
        except SessionNotFound, e:
            log.error("No session found: %s" % e)
            raise SessionNotFoundMsg()

        except SessionExpired, e:
            log.error("Session expired: %s" % e)
            raise SessionExpiredMsg()

        except SessionCertTimeError, e:
            log.error("Session cert. time error: %s" % e)
            raise InvalidSessionMsg()
            
        except InvalidSession, e:
            log.error("Invalid user session: %s" % e)
            raise InvalidSessionMsg()

        except Exception, e:
            log.error("Request from Session Manager [%s] to Attribute "
                      "Authority [%s] for attribute certificate: %s: %s" % 
                      (sessionManagerURI,
                       attributeAuthorityURI,
                       e.__class__, e))
            raise AttributeCertificateRequestError()
            
    def _getAttributeCertificateFromAttributeAuthority(self,
                                                       attributeAuthorityURI,
                                                       username):
        '''Retrieve an Attribute Certificate direct from an Attribute
        Authority.  This method is invoked if no session ID or Session 
        Manager endpoint where provided
        
        @type username: basestring
        @param username: user identifier - may be an OpenID URI
        @type attributeAuthorityURI: basestring
        @param attributeAuthorityURI: URI to Attribute Authority service
        @rtype: ndg.security.common.AttCert.AttCert
        @return: Attribute Certificate containing user roles
        '''
        
        log.debug("PIP._getAttributeCertificateFromAttributeAuthority ...")
       
        try:
            # Create Attribute Authority client - if a file path was set, 
            # settingare read  from a separate config file section otherwise, 
            # from the PDP config object
            aaClnt = AttributeAuthorityClient(
                            uri=attributeAuthorityURI,
                            sslCACertFilePathList=self.sslCACertFilePathList,
                            cfg=self.wssecurityCfg)
        except Exception:
            log.error("Creating Attribute Authority client: %s",
                      traceback.format_exc())
            raise InitSessionCtxError()
        
         
        try:
            # Make request for attribute certificate
            return aaClnt.getAttCert(userId=username)
        
        
        except AA_AttributeRequestDenied:
            log.error("Request for attribute certificate denied: %s",
                      traceback.format_exc())
            raise AttributeCertificateRequestDenied()
        
        # TODO: handle other specific Exception types here for more fine
        # grained response info

        except Exception, e:
            log.error("Request to Attribute Authority [%s] for attribute "
                      "certificate: %s: %s", attributeAuthorityURI,
                      e.__class__, traceback.format_exc())
            raise AttributeCertificateRequestError()
        
