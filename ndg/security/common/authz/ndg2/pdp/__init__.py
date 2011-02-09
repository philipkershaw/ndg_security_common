"""NDG Policy Decision Point Package - contains abstract interface to PEP

The PDP makes authorisation decisions based on the access constraints applying
to a resource and the access rights of a user requesting it

Adapted from original gatekeeper.py code

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

class PDPError(Exception):
    """Base class for PDP exceptions"""
    
class PDPUserAccessDenied(PDPError):
    """Access Denied"""
    def __init__(self, msg=None):
        PDPError.__init__(self, msg or PDPUserAccessDenied.__doc__)
 
class PDPUserInsufficientPrivileges(PDPError):
    """Insufficient privileges to access resource"""
    def __init__(self, msg=None):
        PDPError.__init__(self, msg or PDPUserInsufficientPrivileges.__doc__)
   
class PDPUserNotLoggedIn(PDPError):
    """User is not logged in"""
    def __init__(self, msg=None):
        PDPError.__init__(self, msg or PDPUserNotLoggedIn.__doc__)

class PDPMissingResourceConstraints(PDPError):
    """Access constraints for resource are not set correctly"""
    def __init__(self, msg=None):
        PDPError.__init__(self, msg or PDPMissingResourceConstraints.__doc__)

class PDPMissingUserHandleAttr(PDPError):
    """User session information is not set correctly"""
    def __init__(self, msg=None):
        PDPError.__init__(self, msg or PDPMissingUserHandleAttr.__doc__)
        
class PDPUnknownResourceType(PDPError):
    """The type for requested resource is not known"""
    def __init__(self, msg=None):
        PDPError.__init__(self, msg or PDPUnknownResourceType.__doc__)
            
 
class PDPInterface(object):
    """PEP (Gatekeeper) abstract interface to a Policy Decision Point
    
    PDPs must adhere to this interface by sub-classing from it"""
    
    def __init__(self, 
                 cfg=None, 
                 cfgSection='DEFAULT',
                 **cfgKw):
        """PDPInterface(cfgFilePath|cfg|**cfgKw)
        
        @type cfg: string / ConfigParser
        @param cfg: 
        @type cfg: file path to configuration file or ConfigParser object to 
        retrieve parameters from 
        @type cfgSection: string
        @param cfgSection: sets the section name to retrieve config params 
        from
        @type cfgKw: dict
        @param cfgKw: set parameters as key value pairs."""
        raise NotImplementedError("%s\n%s" % (PDPInterface.__doc__,
                                              PDPInterface.__init__.__doc__))
    
        
    def accessPermitted(self, resrcHandle, userHandle, accessType, *arg, **kw):
        """Make an Access control decision with this behaviour:
        
        @type resrcHandle: any - determined by derived class PDP
        @param resrcHandle: a handle to the resource to make access decision
        for.  This could be for example a resource ID string, or a dict or 
        other object to hold resource information required by the PDP
        
        @type userHandle: any - determined by derived class PDP
        @param userHandle: a handle to the user requesting access.  
        e.g. a user ID, an attribute certificate or a handle to a service 
        which can be interrogated to get the required information
        
        @type accessType: any - determined by derived class PDP
        @param accessType: the type of access being requested e.g. read,
        read/write, put etc.
        
        @rtype: bool
        @return: True if access permitted; False if denied or else raise
        an Exception
        
        Nb. 
        
         * *arg and **kw are included to enable further customisation,
        resrcHandle, userHandle and accessType are merely indicators.
        
         * The alias to this method 'accessPermitted'
         
         * Derived classes should keep to the exception types in this file
         where possible.  New exception types should inherit from PDPError.
         Detailed error information should be left out of the exception
         message and put in the error log instead"""
        raise NotImplementedError("%s\n%s" % (PDPInterface.__doc__,
                                  PDPInterface.accessPermitted.__doc__))
        return False
    
    # Alias for convenience
    def __call__(self, *arg, **kw):
        return self.accessPermitted(*arg, **kw)
    