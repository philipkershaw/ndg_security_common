"""OpenSSL utilities module - contains OpenSSLConfig class for
parsing OpenSSL configuration files

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "08/02/07"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'

import re
import os
from ConfigParser import SafeConfigParser


def m2_get_dn_field(dn, field_name, field_sep=None, name_val_sep=None):
    '''Convenience utility for parsing fields from X.509 subject name returned 
    from M2Crypto API'''
    if field_sep is None:
        field_sep = ','
    
    if name_val_sep is None:
        name_val_sep = '='
        
    for f in dn.split(field_sep):
        name, val = f.strip().split(name_val_sep)
        if name.upper() == field_name:
            return val

def m2_get_cert_ext_values(cert, ext_name, field_sep=None, field_prefix=None):
    '''Get subject alt names from M2Crypto.X509.X509 cert object -
    return None if none found
    
    e.g.
    
    ``m2_get_cert_ext_values(cert, 'subjectAltName, field_prefix="DNS:", field_sep=",")``
    '''
    if field_prefix is None:
        field_prefix = '' # 'DNS:' for subject alt names prefix
        
    for i in cert.get_ext_count():
        ext = cert.get_ext_at(i)
        if ext.get_name() == ext_name:
            val = ext.get_value()
            if field_sep is None:
                yield val
            else:
                for i in val.split(field_sep):
                    yield i.strip()[len(field_prefix)] 
                    
                    
class X500DNError(Exception):
    """Exception handling for NDG X.500 DN class."""


class X500DN(object):
    "Manipulation of X.500 Distinguished name / X.509 subject names"
    
    # Class attribute - look-up mapping short name attributes to their long
    # name equivalents
    # * private *
    SHORT_NAME_LUT = {
        'commonName':               'CN',
        'organisationalUnitName':   'OU',
        'organisation':             'O',
        'countryName':              'C',
        'emailAddress':             'EMAILADDRESS',
        'localityName':             'L',
        'stateOrProvinceName':      'ST',
        'streetAddress':            'STREET',
        'domainComponent':          'DC',
        'userid':                   'UID'
    }
    SLASH_PARSER_RE_STR = '/(%s)=' % '|'.join(SHORT_NAME_LUT.keys() + 
                                              SHORT_NAME_LUT.values())    
    SLASH_PARSER_RE = re.compile(SLASH_PARSER_RE_STR)

    COMMA_PARSER_RE_STR = '[,]?\s*(%s)=' % '|'.join(SHORT_NAME_LUT.keys() + 
                                                    SHORT_NAME_LUT.values())    
    COMMA_PARSER_RE = re.compile(COMMA_PARSER_RE_STR)
    
    def __init__(self, dn=None, separator=None):

        """Create a new X.500 Distinguished Name

        @type dn: basestring
        @param dn: initialise using a distinguished name string
        @type separator: basestring
        @param: separator: separator used to delimit dn fields - usually '/' 
        or ','.  If dn is input and separator is omitted the separator 
        character will be automatically parsed from the dn string.
        """
        
        # Private key data
        self.__dat = {}.fromkeys(self.__class__.SHORT_NAME_LUT.values())
        self.__separator = None
        
        # Check for separator from input
        if separator is not None:
            if not isinstance(separator, basestring):
                raise X500DNError("dn Separator must be a valid string")

            separator_ = separator.lstrip()
            
            # Check for single character but allow trailing space chars
            if len(separator_) != 1:
                raise X500DNError("dn separator must be a single character")

            self.__separator = separator_
        
        if dn is not None:
            # Separator can be parsed from the input DN string - only attempt
            # if no explicit separator was input
            if self.__separator is None:
                self.__separator = self.parse_separator(dn)
                
            # Split Distinguished name string into constituent fields
            self.deserialise(dn)

    @classmethod
    def from_string(cls, dn):
        """Convenience method for parsing DN string into a new instance
        """
        return cls(dn=dn)

    def __repr__(self):
        """Give representation based on underlying dict object"""
        return repr(self.__dat)
        
    def __str__(self):
        """Behaviour for print and string statements - convert DN into
        serialised format."""
        return self.serialise()
        
    def __eq__(self, x500dn):
        """Return true if the all the fields of the two DNs are equal"""
        
        if not isinstance(x500dn, X500DN):
            return False

        return self.__dat.items() == x500dn.items()
   
    def __ne__(self, x500dn):
        """Return true if the all the fields of the two DNs are equal"""
        
        if not isinstance(x500dn, X500DN):
            return False

        return self.__dat.items() != x500dn.items()
  
    def __delitem__(self, key):
        """Prevent keys from being deleted."""
        raise NotImplementedError()

    def __getitem__(self, key):

        # Check input key
        if self.__dat.has_key(key):

            # key recognised
            return self.__dat[key]
        
        elif X500DN.__shortNameLUT.has_key(key):

            # key not recognised - but a long name version of the key may
            # have been passed
            shortName = X500DN.__shortNameLUT[key]
            return self.__dat[shortName]

        else:
            # key not recognised as a short or long name version
            raise KeyError('Key "' + key + '" not recognised for X500DN')

    def __setitem__(self, key, item):
        
        # Check input key
        if self.__dat.has_key(key):

            # key recognised
            self.__dat[key] = item
            
        elif X500DN.__shortNameLUT.has_key(key):
                
            # key not recognised - but a long name version of the key may
            # have been passed
            shortName = X500DN.__shortNameLUT[key]
            self.__dat[shortName] = item
            
        else:
            # key not recognised as a short or long name version
            raise KeyError('Key "' + key + '" not recognised for X500DN')

    def clear(self):
        raise NotImplementedError()

    def copy(self):
        import copy
        return copy.copy(self)

    def keys(self):
        return self.__dat.keys()

    def items(self):
        return self.__dat.items()

    def values(self):
        return self.__dat.values()

    def has_key(self, key):
        return self.__dat.has_key(key)

    # 'in' operator
    def __contains__(self, key):
        return self.has_key(key)

    def get(self, *arg):
        return self.__dat.get(*arg)
      
    def serialise(self, separator=None):
        """Combine fields in Distinguished Name into a single string."""
        
        if separator:
            if not isinstance(separator, basestring):
                raise X500DNError("Separator must be a valid string")            
        else:
            # Default to / if no separator is set
            separator = '/'


        # If using '/' then prepend DN with an initial '/' char
        if separator == '/':
            sDN = separator
        else:
            sDN = ''
     
        dnList = []
        for (key, val) in self.__dat.items():
            if val:
                if isinstance(val, tuple):
                    dnList += [separator.join(["%s=%s" % (key, valSub) \
                                               for valSub in val])]
                else:
                    dnList += ["%s=%s" % (key, val)]
                
        sDN += separator.join(dnList)
                                
        return sDN

    serialize = serialise
    
    def deserialise(self, dn, separator=None):
        """Break up a DN string into it's constituent fields and use to
        update the object's dictionary"""
        
        if separator:
            if not isinstance(separator, basestring):
                raise X500DNError("Separator must be a valid string")
        else:
            separator = self.__separator


        # If no separator has been set, parse if from the DN string            
        if separator is None:
            separator = self.parse_separator(dn)

        if separator == '/':
            parserRe = self.__class__.SLASH_PARSER_RE
            
        elif separator == ',':
            parserRe = self.__class__.COMMA_PARSER_RE
        else:
            raise X500DNError("DN field separator %r not recognised" % 
                              self.__separator)
            
        try:
            dnFields = parserRe.split(dn)
            if len(dnFields) < 2:
                raise X500DNError("Error parsing DN string: \"%s\"" % dn)

            items = zip(dnFields[1::2], dnFields[2::2])
            
            # Reset existing dictionary values
            self.__dat.fromkeys(self.__dat, '')
            
            # Strip leading and trailing space chars and convert into a
            # dictionary
            parsedDN = {}
            for key, val in items:
                key = key.strip()
                if key in parsedDN:
                    if isinstance(parsedDN[key], tuple):
                        parsedDN[key] = tuple(list(parsedDN[key]) + [val])
                    else:
                        parsedDN[key] = (parsedDN[key], val)
                else:
                    parsedDN[key] = val
                
            # Copy matching DN fields
            for key, val in parsedDN.items():
                if (key not in self.__dat and 
                    key not in self.__class__.SHORT_NAME_LUT):
                    raise X500DNError('Invalid field "%s" in input DN string' %
                                      key)

                self.__dat[key] = val

        except Exception, excep:
            raise X500DNError("Error de-serialising DN \"%s\": %s" %
                              (dn, str(excep)))

    deserialize = deserialise
    
    def parse_separator(self, dn):
        """Attempt to parse the separator character from a given input
        DN string.  If not found, return None

        DNs don't use standard separators e.g.

        /C=UK/O=eScience/OU=CLRC/L=DL/CN=AN Other
        CN=SUM Oneelse,L=Didcot, O=RAL,OU=SSTD

        This function isolates and identifies the character.  - In the above,
        '/' and ',' respectively"""


        # Make a regular expression containing all the possible field
        # identifiers with equal sign appended and 'or'ed together.  \W should
        # match the separator which preceeds the field name. \s* allows any
        # whitespace between field name and field separator to be taken into
        # account.
        #
        # The resulting match should be a list.  The first character in each
        # element in the list should be the field separator and should be the
        # same
        regExpr = '|'.join(['\W\s*'+i+'=' for i in self.__dat.keys()])
        match = re.findall(regExpr, dn)
            
        # In the first example above, the resulting match is:
        # ['/C=', '/O=', '/OU=', '/L=']
        # In each element the first character is the separator
        sepList = [i[0:1] for i in match]

        # All separators should be the same character - return None if they
        # don't match
        if not [i for i in sepList if i != sepList[0]]:
            return sepList[0]
        else:
            return None

    @classmethod
    def parse(cls, dn):
        """Convenience method to create an X500DN object from a DN string
        @type dn: basestring
        @param dn: Distinguished Name 
        """
        return cls(dn=dn)
    

class OpenSSLConfigError(Exception):
    """Exceptions related to OpenSSLConfig class"""   


class OpenSSLConfig(SafeConfigParser, object):
    """Wrapper to OpenSSL Configuration file to allow extraction of
    required distinguished name used for making certificate requests
    
    @type _certReqDNParamName: tuple
    @cvar _certReqDNParamName: permissable keys for Distinguished Name
    (not including CN which gets set separately).  This is used in __setReqDN
    to check input
    
    @type _caDirPat: string
    @cvar _caDirPat: sub-directory path to CA config directory
    @type __gridCASubDir: string
    @cvar __gridCASubDir: sub-directory of globus user for CA settings"""
    
    _certReqDNParamName = [
       'C', 
       'serialNumber', 
       'organizationName', 
       'CN', 
       'SP', 
       'commonName', 
       'L', 
       'stateOrProvinceName', 
       'ST', 
       'emailAddress', 
       'O', 
       'localityName', 
       'GN', 
       'surname', 
       'OU', 
       'givenName', 
       'Email', 
       'organizationUnitName', 
       'SN'
    ]
    
    _caDirPat = re.compile('\$dir')
    
    __gridCASubDir = os.path.join(".globus", "simpleCA")

    
    def __init__(self, filePath=None, caDir=None):
        """Initial OpenSSL configuration optionally setting a file path to
        read from
        
        @type filePath: string        
        @param filePath: path to OpenSSL configuration file
        
        @type caDir: string
        @param caDir: directory for SimpleCA.  This is substituted for $dir
        in OpenSSL config file where present.  caDir can be left out in 
        which case the substitution is not done"""
        
        SafeConfigParser.__init__(self)
        
        self.__reqDN = None
        self.__setFilePath(filePath)

        # Set-up CA directory
        self.setCADir(caDir)

            
    def __setFilePath(self, filePath):
        """Set property method
        @type filePath: string
        @param filePath: path for OpenSSL configuration file"""
        if filePath is not None:
            if not isinstance(filePath, basestring):
                raise OpenSSLConfigError, \
                    "Input OpenSSL config file path must be a string"

            try:
                if not os.access(filePath, os.R_OK):
                    raise OpenSSLConfigError, "not found or no read access"
                                         
            except Exception, e:
                raise OpenSSLConfigError, \
                    "OpenSSL config file path is not valid: \"%s\": %s" % \
                    (filePath, str(e))
                    
        self.__filePath = filePath

    def __getFilePath(self):
        """Get property method
        @rtype: string
        @return: file path for OpenSSL configuration file"""
        return self.__filePath

    filePath = property(fget=__getFilePath,
                        fset=__setFilePath,
                        doc="file path for configuration file")
            
    def setCADir(self, caDir):
        """Set property method
        @type caDir: string
        @param caDir: path for OpenSSL configuration file"""
        if caDir is None:
            # Try to set default from 'HOME' env variable
            homeDir = os.environ.get('HOME')
            if homeDir:
                self.__caDir = os.path.join(os.environ['HOME'], 
                                            self.__gridCASubDir)
            else:
                self.__caDir = None
        else:
            if not isinstance(caDir, basestring):
                raise OpenSSLConfigError, \
                    "Input OpenSSL CA directory path must be a string"

            try:
                if not os.access(caDir, os.R_OK):
                    raise OpenSSLConfigError, "not found or no read access"
                                         
            except Exception, e:
                raise OpenSSLConfigError, \
                    "OpenSSL CA directory path is not valid: \"%s\": %s" % \
                    (caDir, str(e))
                    
        self.__caDir = caDir  

    def __getCADir(self):
        """Get property method
        @rtype caDir: string
        @return caDir: directory path for CA configuration files"""
        return self.__caDir

    caDir = property(fget=__getCADir,
                     fset=setCADir,
                     doc="directory path for CA configuration files")

    def __getReqDN(self):
        """Get property method
        @rtype reqDN: dict
        @return reqDN: Distinguished Name for certificate request"""
        return self.__reqDN

    def __setReqDN(self, reqDN):
        """Set property method
        @type reqDN: dict
        @param reqDN: Distinguished Name for certificate request"""
        if not isinstance(reqDN, dict):
            raise AttributeError, "Distinguished Name must be dict type"
        
        invalidKw = [k for k in dict \
                     if k not in self.__class__._certReqDNParamName]
        if invalidKw:
            raise AttributeError, \
    "Invalid certificate request keyword(s): %s.  Valid keywords are: %s" % \
    (', '.join(invalidKw), ', '.join(self.__class__._certReqDNParamName))

        self.__reqDN = reqDN

    reqDN = property(fget=__getReqDN,
                     fset=__setReqDN,
                     doc="Distinguished Name for certificate request")
    
    def read(self):
        """Override base class version to avoid parsing error with the first
        'RANDFILE = ...' part of the openssl file.  Also, reformat _sections 
        to allow for the style of SSL config files where section headings can 
        have spaces either side of the brackets e.g. 
        [ sectionName ] 
        
        and comments can occur on the same line as an option e.g. 
        option = blah # This is option blah
        
        Reformat _sections to """
        try:
            file_ = open(self.__filePath)
            fileTxt = file_.read()
        except Exception, e:
            raise OpenSSLConfigError, \
                "Error reading OpenSSL config file \"%s\": %s" % \
                                                    (self.__filePath, str(e))

        idx = re.search('\[\s*\w*\s*\]', fileTxt).span()[0]
        file_.seek(idx)
        SafeConfigParser.readfp(self, file_)
        
        # Filter section names and reomve comments from options
        for section, val in self._sections.items():
            newSection = section
            self._sections[newSection.strip()] = \
                                    dict([(opt, self._filtOptVal(optVal))
                                          for opt, optVal in val.items()])
            del self._sections[section]
       
        self._set_required_dn_params()

    
    def _filtOptVal(self, optVal):
        """For option value, filter out comments and substitute $dir with
        the CA directory location
        
        @type optVal: string
        @param optVal: option value"""
        filtVal = optVal.split('#')[0].strip()
        if self.__caDir:
            # Replace $dir with CA directory path
            return self.__class__._caDirPat.sub(self.__caDir, filtVal)
        else:
            # Leave $dir in place as no CA directory has been set
            return filtVal

    def readfp(self, fp):
        """Set to not implemented as using a file object could be problematic
        given read() has to seek ahead to the first actual section to avoid
        parsing errors"""
        raise NotImplementedError, "Use read method instead"
        self._parseReqDN()

    def _set_required_dn_params(self):
        """Set Required DN parameters from the configuration file returning
        them in a dictionary"""
        
        # Nb. Match over line boundaries
        try:
            self.__reqDN = \
            {
                'O': self.get('req_distinguished_name', 
                              '0.organizationName_default'),
                'OU': self.get('req_distinguished_name', 
                               '0.organizationalUnitName_default')
            }
        except Exception, e:
            raise OpenSSLConfigError, \
            'Error setting content of Distinguished Name from file "%s": %s'%\
                                                    (self.__filePath, str(e))