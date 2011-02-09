"""NDG Gatekeeper - A PEP (Policy Enforcement Point) enforces authorisation 
decision made by a PDP (Policy Decision Point)

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

# For parsing of properties file
from os.path import expandvars as expVars

# Expand environment vars in paths
import os

# System path modification for module import
import sys

from ConfigParser import SafeConfigParser
from ndg.security.common.AttCert import *
from ndg.security.common.authz.pdp import PDPInterface

class PEPError(Exception):
    """Exception handling for NDG Policy Enforcement Point class."""

class PDPInitError(PEPError):
    """Errors importing and instantiating Policy Decision Point class"""

            
class PEP(object):
    """NDG Policy Enforcement Point class - determines whether a given 
    Attribute Certificate can access a given resource."""
    
    defParam = {'pdpModFilePath': None,
                'pdpModName': '<pdpModName>',
                'pdpClassName': '<pdpClassName>',
                'pdpCfgFilePath': None,
                'pdpCfgSection': 'DEFAULT'}
    
    def __init__(self,
                 cfg=None,
                 cfgSection='DEFAULT',
                 pdpCfgKw={},
                 **prop):
        '''Initialise settings from a config file and/or keyword settings
        
        @type cfg: string / ConfigParser object
        @param cfg: if a string type, this is interpreted as the file path to
        a configuration file, otherwise it will be treated as a ConfigParser 
        object 
        @type cfgSection: string
        @param cfgSection: sets the section name to retrieve config params 
        from
        @type pdpCfgKw: dict
        @param pdpCfgKw: parameters to pass to PDP interface - alternative to
        passing settings in a config file or config object.  Keywords override
        any duplicates set by the latter.
        @type prop: dict
        @param prop: set parameters as key value pairs.'''
         
        log.debug("PEP.__init__ ...")
        self._pdp = None
        self._pdpCfgKw = pdpCfgKw
        
        if isinstance(cfg, basestring):
            log.debug('Setting PEP config from file: "%s" ...' % cfg)
            self._cfg = SafeConfigParser()
            self.readConfig(cfg)
        else:
            log.debug('Setting PEP config from existing config object ...')
            self._cfg = cfg
            
        if cfg: # i.e. at least some kind of config was input
            self.parseConfig(cfgSection)
            
        # Any keywords set will override equivalent file property settings
        # Copy directly into attribute of this object
        for paramName in prop:
            if paramName not in PEP.defParam:
                raise AttributeError(
                            'Keyword "%s" is not a valid config parameter' % \
                            paramName)
            setattr(self, paramName, expVars(prop['paramName']))

        # Default parameters if not set above
        for paramName in PEP.defParam:
            if not hasattr(self, paramName):
                setattr(self, paramName, PEP.defParam[paramName])
        
        if not hasattr(self, 'pdpCfgSection'):
            self.pdpCfgSection = 'DEFAULT'
            
        # Check for minimum param settings necessary for initialising a PDP 
        # object (the module can be on the existing class path)
        if getattr(self, 'pdpModName', None) and \
           getattr(self, 'pdpClassName', None):
            # Initialize if all required resource URI class properties are set
            self.initPDPInterface()
       
        
    def initPDPInterface(self):
        """Set-up PDP interface to PEP"""
        
        log.debug("PEP.initPDPInterface ...")
        sysPathBak = None # extra bullet proofing for finally block
        try:
            try:
                # Temporarily extend system path ready for import
                if self.pdpModFilePath:
                    sysPathBak = sys.path[:]
                    sys.path.append(self.pdpModFilePath)

                # Import module name specified in properties file
                pdpMod = __import__(self.pdpModName,
                                    globals(),
                                    locals(),
                                    [self.pdpClassName])
    
                pdpClass = eval('pdpMod.' + self.pdpClassName)

            finally:
                if sysPathBak:
                    sys.path[:] = sysPathBak
                                
        except KeyError, e:
            raise PDPInitError('Importing PDP module, key not recognised: %s' %
                               e)                          
        except Exception, e:
            raise PDPInitError('Importing PDP module: %s' % e)


        # Check class inherits from PEPResrc abstract base class
        if not issubclass(pdpClass, PDPInterface):
            raise PDPInitError("PDP interface class %s must be derived from "
                               "PDPInterface" % self.pdpClassName)


        # Instantiate custom class
        self._pdp = pdpClass(cfg=self.pdpCfgFilePath or self._cfg,
                             cfgSection=self.pdpCfgSection,
                             **self._pdpCfgKw)            


    def readConfig(self, cfgFilePath):
        """Read the configuration file"""
        self._cfg.read(cfgFilePath)


    def parseConfig(self, section='DEFAULT'):
        '''Extract config properties for the interface to the PDP'''
        
        log.debug("PEP.parseConfig ...")
        
        # Copy directly into attribute of this object
        for paramName in PEP.defParam:
            if self._cfg.has_option(section, paramName):  
                val = expVars(self._cfg.get(section, paramName, None))
                setattr(self, paramName, val)
            else:
                setattr(self, paramName, PEP.defParam[paramName])

   
    def __call__(self, resrcHandle, userHandle, accessType, *arg, **kw):
        """Make an Access control decision with this behaviour:
        
        @type resrcHandle: any - determined by the PDP used
        @param resrcHandle: a handle to the resource which the PEP protects.  
        This could be for example a resource ID string, or a dict or other 
        object to hold resource information required by the PDP
        
        @type userHandle: any - determined by the PDP used
        @param userHandle: a handle to the user requesting access.  
        e.g. a user ID, an attribute certificate or a handle to a service 
        which can be interrogated to get the required information
        
        @type accessType: any - determined by the PDP used
        @param accessType: the type of access being requested e.g. read,
        read/write, put etc.
        
        @rtype: bool
        @return: True if access permitted; False if denied or else raise
        an Exception
        
        Nb. 
        
        *arg and **kw are included to enable further customisation,
        resrcHandle, userHandle and accessType are merely indicators.
        
        The alias to this method 'accessPermitted'"""
        
        if self._pdp is None:
            raise PDPInitError("PDP object is not set - ensure "
                               "initPDPInterface has been called and the "
                               "relevant configuration parameters have been "
                               "set")
            
        return self._pdp.accessPermitted(resrcHandle, 
                                         userHandle, 
                                         accessType, 
                                         *arg, 
                                         **kw)
        
    accessPermitted = __call__
    
    
def accessPermitted():
    '''Convenience wrapper routine for PEP'''
