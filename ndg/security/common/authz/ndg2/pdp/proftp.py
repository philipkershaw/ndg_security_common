"""NDG Policy Decision Point for BADC datasets secured with Proftp .ftpaccess
files

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "04/04/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id:gatekeeper.py 3079 2007-11-30 09:39:46Z pjkersha $"

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
    PDPUserInsufficientPrivileges
    
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


class ProftpPDP(PDPInterface):
    """Make access control decision based on access constraints contained in
    ProFTP .ftpaccess file and a user security token"""

    defParam = {'aaURI': '',
                'sslCACertFilePathList': [],
                'tracefile': None,
                'acCACertFilePathList': [], 
                'wssCfgFilePath': None,
                'wssCfgSection': 'DEFAULT',
                'acIssuer': ''}
       
    def __init__(self, cfg=None, cfgSection='DEFAULT', **cfgKw):
        """Initialise settings for WS-Security and SSL for SOAP
        call to Session Manager
        
        @type cfg: string / ConfigParser object
        @param cfg: if a string type, this is interpreted as the file path to
        a configuration file, otherwise it will be treated as a ConfigParser 
        object 
        @type cfgSection: string
        @param cfgSection: sets the section name to retrieve config params 
        from
        @type cfgKw: dict
        @param cfgKw: set parameters as key value pairs.
        """
        
        self.cfgFilePath = cfg
        self.resrcURI = None
        self.securityElement = None
        self.userHandle = None
        
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
            if paramName in ProftpPDP.defParam:
                # Keywords are deleted as they are set
                setattr(self, paramName, cfgKw.pop('paramName'))
                
        # Remaining keys must be for WS-Security config
        self.wssCfg = cfgKw    

           
    def _readConfig(self, cfgFilePath):
        '''Read PDP configuration file'''
        self._cfg.read(cfgFilePath)


    def _parseConfig(self, section='DEFAULT'):
        '''Extract parameters from _cfg config object'''
        log.debug("ProftpPDP._parseConfig ...")

        # Copy directly into attribute of this object
        for paramName, paramVal in ProftpPDP.defParam.items():
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
        @param resrcHandle: contains resource groups and user IDs determining
        access
        
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
        
        @type: dict
        @param userHandle: containing user session ID and Session Manager 
        address."""

        # User handle contains 'h' = Session Manager URI and 'sid' user 
        # Session ID
        try:
            self.smURI = userHandle['h']
            self.userSessID = userHandle['sid']
        except KeyError, e:
            log.error("User handle missing key %s" % e)
            raise PDPUserNotLoggedIn()

        
        # Retrieve Attirbute Certificate from user's session held by
        # Session Manager
        attCert = self._pullUserSessionAttCert()
        
        # Check its validity
        self._checkAttCert(attCert)
            
        # Check cert against resource constraints
        self._checkProFTPResrcConstraints(resrcHandle, attCert)
        
        # Removed AC content from log message -       
        # Including the Attribute Certificate makes it appear in stdout?! -
        # and therefore in the HTML output!
        log.info('ProftpPDP - access granted for user "%s" ' % \
                 attCert.userId + 'to "%s"' % \
                 resrcHandle.get('filePath', "<RESOURCE>"))


    def _checkProFTPResrcConstraints(self, resrcHandle, attCert):
        """Check ProFTP access constraints and set the required role(s) for 
        access.  Perl BADC::FTPaccess and NDG::Security::Client code
        casrry out preliminary checks e.g. is access to the resource 
        constrained by a .ftpaccess file at all or if one exists is it public
        access.  This method deals with constraints where comparison with
        Attribute Certificate is needed i.e. info on what roles the user has 
        and/or their id.
        
        @type resrcHandle: dict
        @param resrcHandle: resource user and group constraints
        @type attCert: ndg.security.common.AttCert.AttCert
        @param attCert: user Attribute Certificate
        
        @raise PDPUserInsufficientPrivileges: if user doesn't have the 
        required roles or ID for access
        """
        log.debug("ProftpPDP._checkProFTPResrcConstraints ...")
        
        userRoles = attCert.roles
        log.debug("user has these roles = %s" % userRoles)
        
        # Check based on allowed groups
        allowedGroups = resrcHandle.get('allowedGroups', [])
        for allowedGroup in allowedGroups:
             if allowedGroup in userRoles:
                 log.info('ProftpPDP: User role "%s" is in .ftpaccess allowed '
                          'groups: %s'%(allowedGroup,', '.join(allowedGroups)))
                 return
                 
        # User must be in all of these groups
        requiredGroupSets = resrcHandle.get('requiredGroups', [])
        
        # Groups are organised into sets
        for requiredGroupSet in requiredGroupSets:
            # Each set must be parsed from a string of groups delimited by 
            # 'and's
            log.debug("requiredGroupSet = %s" % requiredGroupSet)
            requiredGroups = requiredGroupSet.split(' and ')
            
            userHasAllGroups = True
            for group in requiredGroups:
                if group not in userRoles:
                    userHasAllGroups = False
                    break

            if userHasAllGroups:
                log.info('ProftpPDP: User has all the required .ftpaccess '
                         'groups: %s' % ', '.join(requiredGroups))
                return
         
   
        allowedUsers = resrcHandle.get('allowedUsers', [])
        
        # .ftpaccess expects a user ID but AC user ID may be a X.509 cert.
        # Distinguished Name - try conversion
        if attCert.userId == str(attCert.holderDN):
            username = attCert.holderDN['CN']
            log.debug('Set username "%s" from AC Holder DN' % username)
        else:
            username = attCert.userId
            log.debug('Set username "%s" from AC user ID' % username)
            
        if username in allowedUsers:
            log.info('ProftpPDP: user ID "%s" is in list of allowed users: '
                     '"%s"' % (username, '", "'.join(allowedUsers)))
            return
        
        
        # Catch all - default to deny access
        log.info('Access denied to resource %s for user "%s" with roles "%s"'%\
                 (resrcHandle, attCert.userId, '", "'.join(userRoles)))
        raise PDPUserInsufficientPrivileges()
    
        
    def _pullUserSessionAttCert(self):
        """Check to see if the Session Manager can deliver an Attribute 
        Certificate with the required role to gain access to the resource
        in question        
        """
        
        log.debug("ProftpPDP._pullUserSessionAttCert ...")
        try:
            # Create Session Manager client
            self.smClnt = SessionManagerClient(uri=self.smURI,
                            sslCACertFilePathList=self.sslCACertFilePathList,
                            tracefile=self.tracefile, 
                            cfg=self.wssCfgFilePath or self._cfg,
                            cfgFileSection=self.wssCfgSection,
                            **self.wssCfg)
        except Exception, e:
            log.error("ProftpPDP: creating Session Manager client: %s" % e)
            raise InitSessionCtxError()
        
                  
        try:
            # Make request for attribute certificate
            attCert = self.smClnt.getAttCert(attributeAuthorityURI=self.aaURI,
                                             sessID=self.userSessID)
            return attCert
        
        except AttributeRequestDenied, e:
            log.info("ProftpPDP - request for attribute certificate denied: "
                     "%s" % e)
            raise PDPUserAccessDenied()
        
        except SessionNotFound, e:
            log.info("ProftpPDP - no session found: %s" % e)
            raise PDPUserNotLoggedIn()

        except SessionExpired, e:
            log.info("ProftpPDP - session expired: %s" % e)
            raise InvalidSessionMsg()

        except SessionCertTimeError, e:
            log.info("ProftpPDP - session cert. time error: %s" % e)
            raise InvalidSessionMsg()
            
        except InvalidSession, e:
            log.info("ProftpPDP - invalid user session: %s" % e)
            raise InvalidSessionMsg()

        except Exception, e:
            log.error("ProftpPDP request for attribute certificate: %s" % e)
            raise AttributeCertificateRequestError()
        

    def _checkAttCert(self, attCert):
        '''Check attribute certificate is valid
        
        @type attCert: ndg.security.common.AttCert.AttCert
        @param attCert: attribute certificate to be check for validity
        
        @raise InvalidAttributeCertificate: if signature is invalid or the
        issuer DN doesn't match the setting in the PDP config'''
        
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
            log.error('ProftpPDP - access denied: Attribute Certificate issuer'
                      ' DN, "%s" ' % attCert.issuerDN + \
                      'must match this data provider\'s Attribute Authority '
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
                   socket.error, socket.sslerror, AttributeError):
               if raiseExcep:
                   raise URLCannotBeOpened()
           
           found = True
         
       finally:
           socket.setdefaulttimeout(defTimeOut)
           
       return found
      
    
def makeDecision(resrcHandle, userHandle, accessType=None, **kw):
    '''One call Wrapper interface to ProftpPDP'''
    return ProftpPDP(**kw)(resrcHandle, userHandle)

import re
# Ported from Perl BADC::FTPaccess class but untested! - it's been possible to
# use the Perl directly instead.  THIS CODE IS NOT IN USE
class FTPAccess(object):    
    '''Routines connected with reading .ftpaccess files used by proftp to 
    control access to directories. Intended for use by web cgi programs.
    Makes some simplifying assumptions about the way the files are used:
   
      o Only the 'closest' .ftpaccess file is read
      o Only the '<limit read>' sections are read
      o Directories are assumed to be either 'public' (indicated by the 
      presence of 'allowall'), or restricted.
      o For restricted datasets, no one except the specified users and/or those
      in the specified groups have access.
   
    This file contains a class for reading the .ftpaccess files, plus the 
    'readAccess' routine, which checks if the given file or directory
    is readable by the current user. 
    '''

    FTPACCESS_FILE = ".ftpaccess";
    
    # Regular expression for valid characters in group name
    GROUP_REGX = "A-Za-z0-9_\-"; 
    
    def __init__(self, filePath):
        '''Constructor of class for reading .ftpaccess file'''
    
        self.filePath = filePath
        
        # Read lines from file into array striping white spaces and comments      
        self.lines = [line.strip() for line in open(file).readlines() \
                      if line.lstrip()[0]!= '#']



    def extractLimitSection(self, limitSectionName):
        '''Returns lines of file within specified 'limit' section'''
        # limitSection = Limit type, eg. 'read', 'write'.
        
        startDelimPat = re.compile('<limit.*\s%s[\s>]' % limitSectionName)
        endDelimitPat = re.compile('<\/limit>')
        limitSection = []
        for line in self.lines:
           if push:
               if endDelimitPat.match(line):
                   break
               limitSection += [line]
    
           if startDelimPat.match(line):
               push = True
    
        return limitSection
    

    def allowedUsers(self, limitSectionName):
    
        users = None
    
        lines = self.extractLimitSection(limitSectionName)
     
        userLinePat = re.compile('^AllowUser')
        userLines = [line for line in lines if userLinePat.match(line)]
        
        userPat = re.compile('allowuser\s+(\w+)')
        users = []
        for userLine in userLines:
            mat = userPat.match(userLine)
            users += [mat.groups()[0]]
    
        return users

    groupLinePat = re.compile('^AllowGroup')
    
    def getAllowedGroups(self, limitSectionName):
        '''Returns list of groups that are allowed access. Ignores any lines 
        containing multiple groups separated by commas.'''

        
        lines = self.extractLimitSection(limitSectionName);
        
        groupLines  = [line for line in lines \
                       if FTPAccess.groupLinePat.match(line)]
        
        groupPat = re.compile('allowgroup\s+([$GROUP_REGX]+)')
        
        groups = []
        for groupLine in groupLines:
            if ',' in groupLine:
                # If it's got a comma then ignore this line
                continue
            
            mat = groupPat.match(groupLine)
            groups += [mat.groups(groupLine)]           
        
        return groups; 


    def getRequiredGroups(self, limitSectionName):
        '''Returns list of any group lines which contain multiple groups 
        separated by comas. These groups are ANDed together. This subroutine 
        returns a list containing one entry for each line containing multiple
        groups (in practice I guess that there will only be one line). Each 
        entry contains the group names separated by ' and '.'''
        
        requiredGroups = []
    
        lines = self.extractLimitSection(limitSectionName);
       
        groupLines  = [line for line in lines \
                       if FTPAccess.groupLinePat.match(line)]
      
        requiredGroupPat = re.compile('^allowgroup\s*/')
        groupDelimPat = re.compile('\s*,\s*')
        for groupLine in groupLines:
            if ',' in groupLine:
                # Multi-group line found
                groups = groupDelimPat.split(groupLine[len('AllowGroup'):])
                groupsTxt = ' and '.join(groups)
                requiredGroups += [groupsTxt]
    
        return requiredGroups; 


    def publicAccess(self, type):    
      lines = self.extractLimitSection(type)
      return 'allowall' in ''.join(lines)


    @classmethod
    def findAllFTPAccessFiles(cls, filePath):
        '''Returns the full names of all .ftpaccess files above the given file
        '''

        #   Remove filename if present
        if os.path.isdir(filePath):
            dirPath = filePath
        else:
            dirPath = os.path.dirname(filePath)
    
        files = []
        while (dirPath):
            checkFile = os.path.join(dirPath, cls.FTPACCESS_FILE)
    
            if os.path.exists(checkFile):     
                files += [checkFile]

            # Traverse up a directory
            parentDirPath = os.path.dirname(dirPath)
            if parentDirPath == dirPath: # root found
                dirPath = None
            else:
                dirPath = parentDirPath

        return files


    @classmethod
    def findNearestFTPAccessFile(cls, filePath):
        '''Returns the full name of the .ftpaccess file closest to the given 
        file.'''
    
        # Remove filename if present
        if os.path.isdir(filePath):
            dirPath = filePath
        else:
            dirPath = os.path.dirname(filePath)
    
        nearestFTPAccessFile = None
        while (dirPath):
            checkFile = os.path.join(dirPath, cls.FTPACCESS_FILE)
    
            if os.path.exists(checkFile):     
                nearestFTPAccessFile = checkFile
                break

            # Traverse up a directory
            parentDirPath = os.path.dirname(dirPath)
            if parentDirPath == dirPath: # root found
                dirPath = None
            else:
                dirPath = parentDirPath
    
        return nearestFTPAccessFile


    def readAccess(cls, filePath):
        '''Check access constraints on a file - it can make an access decision
        if no user attribute info is needed e.g. when constraint is 'public'
        
        @rtype: tuple
        @return: Returns flag indicating if the user is allowed to read the 
        directory containing the given file. Also returns dict giving 
        information about how the result was arived at.'''
        
        # Check that we do actually have an ftpaccess file to interogate. If 
        # not then grant read access
        info = {}
        ftpAccessFile = cls.findNearestFTPAccessFile(filePath)
        try:
            ftpAccess = FTPAccess(ftpAccessFile)
        except IOError:
            info['noObj'] = True;
            return True, info

        info['filePath'] = ftpAccessFile

        #  Check for public access
        if ftpAccess.publicAccess("read"):
            info['public'] = True
            return True, info

        #  Check if user is in one of the allowed groups
        allowedGroups = ftpAccess.getAllowedGroups("read")    
        info['allowedGroups'] = allowedGroups

        #  Check any lines that contain multiple groups
        requiredGroups = ftpAccess.getRequiredGroups("read")
        info['requiredGroups'] = requiredGroups
    
        # Check if the user's username is explicitly granted access
        allowedUsers = ftpAccess.allowedUsers("read")
        allowedUsers= info['allowedUsers']

        # False because user info is required to determine access decision
        return False, info
    
