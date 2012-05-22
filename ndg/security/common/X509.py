"""X.509 certificate handling class encapsulates M2Crypto.X509

NERC Data Grid Project
"""
__author__ = "P J Kershaw"
__date__ = "05/04/05"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__license__ = "BSD - See LICENSE file in the top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
log = logging.getLogger(__name__)
from warnings import warn # warn of impending certificate expiry

import types
import re
import os
import errno

# Handle not before and not after strings
from time import strptime
from datetime import datetime

import M2Crypto


class X509CertError(Exception):
    """Exception handling for NDG X.509 Certificate handling class."""

class X509CertReadError(X509CertError):
    """Error reading in certificate from file"""

class X509CertParseError(X509CertError):
    """Error parsing a certificate"""
  
class X509CertInvalidNotBeforeTime(X509CertError):
    """Call from X509Cert.isValidTime if certificates not before time is
    BEFORE the current system time"""
    
class X509CertExpired(X509CertError):
    """Call from X509Cert.isValidTime if certificate has expired"""

   
class X509Cert(object):
    "NDG X509 Certificate Handling"

    formatPEM = M2Crypto.X509.FORMAT_PEM
    formatDER = M2Crypto.X509.FORMAT_DER
    
    def __init__(self, filePath=None, m2CryptoX509=None):

        # Set certificate file path
        if filePath is not None:
            if not isinstance(filePath, basestring):
                raise X509CertError("Certificate File Path input must be a "
                                    "valid string")
            
        self.__filePath = filePath            
        self.__dn = None
        self.__dtNotBefore = None
        self.__dtNotAfter = None
        
        if m2CryptoX509:
            self.__setM2CryptoX509(m2CryptoX509)
        else:
            self.__m2CryptoX509 = None

    def read(self, 
             filePath=None, 
             format=None, 
             warningStackLevel=3,
             **isValidTimeKw):
        """Read a certificate from PEM encoded DER format file
        
        @type filePath: basestring
        @param filePath: file path of PEM format file to be read
        
        @type format: int
        @param format: format of input file - PEM is the default.  Set to
        X509Cert.formatDER for DER format
        
        @type isValidTimeKw: dict
        @param isValidTimeKw: keywords to isValidTime() call"""

        if format is None:
            format = X509Cert.formatPEM
        
     	# Check for optional input certificate file path
    	if filePath is not None:
            if not isinstance(filePath, basestring):
                raise X509CertError("Certificate File Path input must be a "
                                    "valid string")
            
            self.__filePath = filePath
       
        try:
            self.__m2CryptoX509 = M2Crypto.X509.load_cert(self.__filePath,
                                                          format=format)
        except Exception, e:
            raise X509CertReadError("Error loading certificate \"%s\": %s" %
                                    (self.__filePath, e))

        # Update DN and validity times from M2Crypto X509 object just
        # created
        self.__setM2CryptoX509()
        
        self.isValidTime(warningStackLevel=warningStackLevel, **isValidTimeKw)

    def parse(self, 
              certTxt, 
              format=None, 
              warningStackLevel=3,
              **isValidTimeKw):
        """Read a certificate input as a string
        
        @type certTxt: basestring
        @param certTxt: PEM encoded certificate to parse 
        
        @type format: int
        @param format: format of input file - PEM is the default.  Set to
        X509Cert.formatDER for DER format
        
        @type isValidTimeKw: dict
        @param isValidTimeKw: keywords to isValidTime() call"""

        if format is None:
            format = X509Cert.formatPEM
            
        try:
            # Create M2Crypto memory buffer and pass to load certificate
            # method
            #
            # Nb. input converted to standard string - buffer method won't
            # accept unicode type strings
#            certBIO = M2Crypto.BIO.MemoryBuffer(str(certTxt))
#            self.__m2CryptoX509 = M2Crypto.X509.load_cert_bio(certBIO)
            self.__m2CryptoX509 = M2Crypto.X509.load_cert_string(str(certTxt),
                                                                 format=format)
        except Exception, e:
            raise X509CertParseError("Error loading certificate: %s" % e)

        # Update DN and validity times from M2Crypto X509 object just
        # created
        self.__setM2CryptoX509()
        
        self.isValidTime(warningStackLevel=warningStackLevel, **isValidTimeKw)
      
    def __setM2CryptoX509(self, m2CryptoX509=None):
        """Private method allows class members to be updated from the
        current M2Crypto object.  __m2CryptoX509 must have been set."""
        
        if m2CryptoX509 is not None:
            if not isinstance(m2CryptoX509, M2Crypto.X509.X509):
                raise TypeError("Incorrect type for input M2Crypto.X509.X509 "
                                "object")
                    
            self.__m2CryptoX509 = m2CryptoX509
                   
        # Get distinguished name
        m2CryptoX509Name = self.__m2CryptoX509.get_subject()

        # Instantiate X500 Distinguished name
        self.__dn = X500DN(m2CryptoX509Name=m2CryptoX509Name)
        
        # Get not before and not after validity times
        #
        # Only option for M2Crypto seems to be to return the times as
        # formatted strings and then parse them in order to create a datetime
        # type
        
        try:
            m2CryptoNotBefore = self.__m2CryptoX509.get_not_before()
            self.__dtNotBefore=self.__m2CryptoUTC2datetime(m2CryptoNotBefore)
                                        
        except Exception, e:
            raise X509CertError("Not Before time: %s" % e)

        try:
            m2CryptoNotAfter = self.__m2CryptoX509.get_not_after()
            self.__dtNotAfter = self.__m2CryptoUTC2datetime(m2CryptoNotAfter)
                                    
        except Exception, e:
            raise X509CertError("Not After time: %s" % e)

    def __getM2CryptoX509(self, m2CryptoX509=None):
        "Return M2Crypto X.509 cert object"
        return self.__m2CryptoX509
    
    m2CryptoX509 = property(fset=__setM2CryptoX509,
                            fget=__getM2CryptoX509,
                            doc="M2Crypto.X509.X509 type")
        
    def toString(self, **kw):
        """Return certificate file content as a PEM format 
        string"""
        return self.asPEM(**kw)
        
    def asPEM(self, filePath=None):
        """Return certificate file content as a PEM format 
        string"""
        
        # Check M2Crypto.X509 object has been instantiated - if not call
        # read method
        if self.__m2CryptoX509 is None:
            self.read(filePath)
            
        return self.__m2CryptoX509.as_pem()

    def asDER(self):
        """Return certificate file content in DER format"""
        
        # Check M2Crypto.X509 object has been instantiated 
        assert(self.__m2CryptoX509)
        return self.__m2CryptoX509.as_der()

    # Make some attributes accessible as read-only
    def __getDN(self):
        """Get X500 Distinguished Name."""
        return self.__dn

    dn = property(fget=__getDN, doc="X.509 Distinguished Name")
    
    def __getVersion(self):
        """Get X.509 Certificate version"""
        if self.__m2CryptoX509 is None:
            return None
        
        return self.__m2CryptoX509.get_version()

    version = property(fget=__getVersion, doc="X.509 Certificate version")
	
    def __getSerialNumber(self):
        """Get Serial Number"""
        if self.__m2CryptoX509 is None:
            return None
        
        return self.__m2CryptoX509.get_serial_number()
    
    serialNumber = property(fget=__getSerialNumber, 
                            doc="X.509 Certificate Serial Number")

    def __getNotBefore(self):
        """Get not before validity time as datetime type"""
        if self.__m2CryptoX509 is None:
            return None
        
        return self.__dtNotBefore

    notBefore = property(fget=__getNotBefore, 
                         doc="Not before validity time as datetime type")
	
    def __getNotAfter(self):
        """Get not after validity time as datetime type"""
        if self.__m2CryptoX509 is None:
            return None
        
        return self.__dtNotAfter

    notAfter = property(fget=__getNotAfter, 
                         doc="Not after validity time as datetime type")
	
    def __getPubKey(self):
        """Get public key
        
        @return: RSA public key for certificate
        @rtype: M2Crypto.RSA.RSA_pub"""
        if self.__m2CryptoX509 is None:
            return None
        
        return self.__m2CryptoX509.get_pubkey()

    pubKey = property(fget=__getPubKey, doc="Public Key")
	
    def __getIssuer(self):
        """Get Certificate issuer"""
        if self.__m2CryptoX509 is None:
            return None
        
        # Return as X500DN type
        return X500DN(m2CryptoX509Name=self.__m2CryptoX509.get_issuer())

    issuer = property(fget=__getIssuer, doc="Certificate Issuer")
    
    def __getSubject(self):
        """Get Certificate subject"""
        if self.__m2CryptoX509 is None:
            return None

        # Return as X500DN type
        return X500DN(m2CryptoX509Name=self.__m2CryptoX509.get_subject())
    
    subject = property(fget=__getSubject, doc="Certificate subject")

    def isValidTime(self, 
                    raiseExcep=False, 
                    expiryWarning=True, 
                    nDaysBeforeExpiryLimit=30,
                    warningStackLevel=2):
        """Check Certificate for expiry

        @type raiseExcep: bool
        @param raiseExcep: set True to raise an exception if certificate is 
        invalid
        
        @type expiryWarning: bool
        @param expiryWarning: set to True to output a warning message if the 
        certificate is due to expire in less than nDaysBeforeExpiryLimit days. 
        Message is sent using warnings.warn and through logging.warning.  No 
        message is set if the certificate has an otherwise invalid time
        
        @type nDaysBeforeExpiryLimit: int
        @param nDaysBeforeExpiryLimit: used in conjunction with the 
        expiryWarning flag.  Set the number of days in advance of certificate
        expiry from which to start outputing warnings
        
        @type warningStackLevel: int
        @param warningStackLevel: set where in the stack to flag the warning
        from.  Level 2 will flag it at the level of the caller of this 
        method.  Level 3 would flag at the level of the caller of the caller
        and so on.
        
        @raise X509CertInvalidNotBeforeTime: current time is before the 
        certificate's notBefore time
        @raise X509CertExpired: current time is after the certificate's 
        notAfter time"""

        if not isinstance(self.__dtNotBefore, datetime):
            raise X509CertError("Not Before datetime is not set")

        if not isinstance(self.__dtNotAfter, datetime):
            raise X509CertError("Not After datetime is not set")
       
        dtNow = datetime.utcnow()
        isValidTime = dtNow > self.__dtNotBefore and dtNow < self.__dtNotAfter

        # Helper string for message output
        if self.__filePath:
            fileInfo = ' "%s"' % self.__filePath
        else:
            fileInfo = ''
             
        
        # Set a warning message for impending expiry of certificate but only
        # if the certificate is not any other way invalid - see below
        if isValidTime and expiryWarning:
            dtTime2Expiry = self.__dtNotAfter - dtNow
            if dtTime2Expiry.days < nDaysBeforeExpiryLimit:
                msg = ('Certificate%s with DN "%s" will expire in %d days on: '
                       '%s' % (fileInfo, 
                               self.dn, 
                               dtTime2Expiry.days, 
                               self.__dtNotAfter))
                warn(msg, stacklevel=warningStackLevel)
                log.warning(msg)
        
                     
        if dtNow < self.__dtNotBefore:
            msg = ("Current time %s is before the certificate's Not Before "
                   'Time %s for certificate%s with DN "%s"' % 
                   (dtNow, self.__dtNotBefore, fileInfo, self.dn))
            log.error(msg)
            if raiseExcep:
                raise X509CertInvalidNotBeforeTime(msg)
            
        elif dtNow > self.__dtNotAfter:
            msg = ('Certificate%s with DN "%s" has expired: the time now is '
                   '%s and the certificate expiry is %s.' %(fileInfo,
                                                            self.dn, 
                                                            dtNow, 
                                                            self.__dtNotAfter))
            log.error(msg)
            if raiseExcep:
                raise X509CertExpired(msg)

        # If exception flag is not set return validity as bool
        return isValidTime




    def __m2CryptoUTC2datetime(self, m2CryptoUTC):
        """Convert M2Crypto UTC time string as returned by get_not_before/
        get_not_after methods into datetime type"""
        
        datetimeRE = "([a-zA-Z]{3} {1,2}\d{1,2} \d{2}:\d{2}:\d{2} \d{4}).*"
        sM2CryptoUTC = None
        
        try:
            # Convert into string
            sM2CryptoUTC = str(m2CryptoUTC)
            
            # Check for expected format - string may have trailing GMT - ignore
            sTime = re.findall(datetimeRE, sM2CryptoUTC)[0]

            # Convert into a tuple
            lTime = strptime(sTime, "%b %d %H:%M:%S %Y")[0:6]

            return datetime(lTime[0], lTime[1], lTime[2],
                            lTime[3], lTime[4], lTime[5])
                                    
        except Exception, e:
            msg = "Error parsing M2Crypto UTC"
            if sM2CryptoUTC is not None:
                msg += ": " + sM2CryptoUTC
                
            raise X509CertError(msg)
	
    def verify(self, pubKey, **kw):
        """Verify a certificate against the public key of the
        issuer
        
        @param pubKey: public key of cert that issued self
        @type pubKey: M2Crypto.RSA.RSA_pub
        @param **kw: keywords to pass to M2Crypto.X509.X509 -
        'pkey'
        @type: dict
        @return: True if verifies OK, False otherwise
        @rtype: bool
        """
        return bool(self.__m2CryptoX509.verify(pubKey, **kw))

    @classmethod
    def Read(cls, filePath, warningStackLevel=4, **isValidTimeKw):
        """Create a new X509 certificate read in from a file"""
        x509Cert = cls(filePath=filePath)  
        x509Cert.read(warningStackLevel=warningStackLevel, **isValidTimeKw)
        
        return x509Cert
    
    @classmethod
    def Parse(cls, x509CertTxt, warningStackLevel=4, **isValidTimeKw):
        """Create a new X509 certificate from string of file content"""
        x509Cert = cls()      
        x509Cert.parse(x509CertTxt, 
                       warningStackLevel=warningStackLevel,
                       **isValidTimeKw)
        
        return x509Cert

    @classmethod
    def fromM2Crypto(cls, m2CryptoX509):
        """Convenience method to instantiate a new object from an M2Crypto
        X.509 certificate object"""
        x509Cert = cls(m2CryptoX509=m2CryptoX509)
        return x509Cert
    
# Alternative AttCert constructors
def X509CertRead(filePath, warningStackLevel=4, **isValidTimeKw):
    """Create a new X509 certificate read in from a file"""

    x509Cert = X509Cert(filePath=filePath)    
    x509Cert.read(warningStackLevel=warningStackLevel, **isValidTimeKw)
    
    return x509Cert

def X509CertParse(x509CertTxt, warningStackLevel=4, **isValidTimeKw):
    """Create a new X509 certificate from string of file content"""

    x509Cert = X509Cert()
    x509Cert.parse(x509CertTxt, 
                   warningStackLevel=warningStackLevel, 
                   **isValidTimeKw)
    
    return x509Cert


class X509StackError(X509CertError):
    """Error from X509Stack type"""


class X509StackEmptyError(X509CertError):
    """Expecting non-zero length X509Stack"""


class X509CertIssuerNotFound(X509CertError):
    """Raise from verifyCertChain if no certificate can be found to verify the
    input"""


class SelfSignedCert(X509CertError):
    """Raise from verifyCertChain if cert. is self-signed and 
    rejectSelfSignedCert=True"""


class X509CertInvalidSignature(X509CertError):
    """X.509 Certificate has an invalid signature"""
       
       
class X509Stack(object):
    """Wrapper for M2Crypto X509_Stack"""
    
    def __init__(self, m2X509Stack=None):
        """Initialise from an M2Crypto stack object
        
        @param m2X509Stack: M2Crypto X.509 stack object
        @type m2X509Stack: M2Crypto.X509.X509_Stack"""
        
        self.__m2X509Stack = m2X509Stack or M2Crypto.X509.X509_Stack()
        
    def __len__(self):
        """@return: length of stack
        @rtype: int"""
        return self.__m2X509Stack.__len__()

    def __getitem__(self, idx):
        """Index stack as an array
        @param idx: stack index
        @type idx: int
        @return: X.509 cert object
        @rtype: ndg.security.common.X509.X509Cert"""
        
        return X509Cert(m2CryptoX509=self.__m2X509Stack.__getitem__(idx))
    
    def __iter__(self):
        """@return: stack iterator
        @rtype: listiterator"""
        return iter([X509Cert(m2CryptoX509=i) for i in self.__m2X509Stack])

    def push(self, x509Cert):
        """Push an X509 certificate onto the stack.
        
        @param x509Cert: X509 object.
        @type x509Cert: M2Crypto.X509.X509,
        ndg.security.common.X509.X509Cert or basestring
        @return: The number of X509 objects currently on the stack.
        @rtype: int"""
        if isinstance(x509Cert, M2Crypto.X509.X509):
            return self.__m2X509Stack.push(x509Cert)
        
        elif isinstance(x509Cert, X509Cert):
            return self.__m2X509Stack.push(x509Cert.m2CryptoX509)
        
        elif isinstance(x509Cert, basestring):
            return self.__m2X509Stack.push(\
                                       X509CertParse(x509Cert).m2CryptoX509)            
        else:
            raise X509StackError("Expecting M2Crypto.X509.X509, ndg.security."
                                 "common.X509.X509Cert or string type")
                
    def pop(self):
        """Pop a certificate from the stack.
        
        @return: X509 object that was popped, or None if there is nothing
        to pop.
        @rtype: ndg.security.common.X509.X509Cert
        """
        return X509Cert(m2CryptoX509=self.__m2X509Stack.pop())

    def asDER(self):
        """Return the stack as a DER encoded string
        @return: DER string
        @rtype: string"""
        return self.__m2X509Stack.as_der()

    def verifyCertChain(self, 
                        x509Cert2Verify=None, 
                        caX509Stack=None,
                        rejectSelfSignedCert=True):
        """Treat stack as a list of certificates in a chain of
        trust.  Validate the signatures through to a single root issuer.  

        @param x509Cert2Verify: X.509 certificate to be verified default is
        last in the stack
        @type x509Cert2Verify: X509Cert
        
        @param caX509Stack: X.509 stack containing CA certificates that are
        trusted.
        @type caX509Stack: X509Stack
        
        @param rejectSelfSignedCert: Set to True (default) to raise an 
        SelfSignedCert exception if a certificate in self's stack is 
        self-signed.  
        @type rejectSelfSignedCert: bool"""
        
        if caX509Stack is None:
            caX509Stack = []
            
        n2Validate = len(self)
        if x509Cert2Verify:
            # One more to validate in addition to stack content
            n2Validate += 1
        else:
            # Validate starting from last on stack - but check first that it's
            # populated
            if n2Validate == 0:
                raise X509StackEmptyError("Empty stack and no x509Cert2Verify "
                                          "set: no cert.s to verify")

            x509Cert2Verify = self[-1]
              
        # Exit loop if all certs have been validated or if find a self 
        # signed cert.
        nValidated = 0
        issuerX509Cert = None
        while nValidated < n2Validate:
            issuerX509Cert = None
            issuerDN = x509Cert2Verify.issuer
            
            # Search for issuing certificate in stack
            for x509Cert in self:
                if x509Cert.dn == issuerDN:
                    # Match found - the cert.'s issuer has been found in the 
                    # stack
                    issuerX509Cert = x509Cert
                    break
                    
            if issuerX509Cert:
                # An issuing cert. has been found - use it to check the 
                # signature of the cert. to be verified
                if not x509Cert2Verify.verify(issuerX509Cert.pubKey):
                    X509CertInvalidSignature('Signature is invalid for cert. '
                                             '"%s"' % x509Cert2Verify.dn)
                
                # In the next iteration the issuer cert. will be checked:
                # 1) search for a cert. in the stack that issued it
                # 2) If found use the issuing cert. to verify
                x509Cert2Verify = issuerX509Cert
                nValidated += 1
            else:
                # All certs in the stack have been searched
                break


        if issuerX509Cert:            
            # Check for self-signed certificate
            if (nValidated == 1 and rejectSelfSignedCert and 
                issuerX509Cert.dn == issuerX509Cert.issuer):

                # If only one iteration occurred then it must be a self
                # signed certificate
                raise SelfSignedCert("Certificate is self signed: [DN=%s]" %
                                     issuerX509Cert.dn)
           
            if not caX509Stack:
                caX509Stack = [issuerX509Cert]
                         
        elif not caX509Stack:
            raise X509CertIssuerNotFound('No issuer certificate found for '
                                         'certificate "%s"' % 
                                         x509Cert2Verify.dn)
            
        for caCert in caX509Stack:
            issuerDN = x509Cert2Verify.issuer
            if caCert.dn == issuerDN:
                issuerX509Cert = caCert
                break
        
        if issuerX509Cert:
            if not x509Cert2Verify.verify(issuerX509Cert.pubKey):
                X509CertInvalidSignature('Signature is invalid for cert. "%s"' %
                                         x509Cert2Verify.dn)
            
            # Chain is validated through to CA cert
            return
        else:
            raise X509CertIssuerNotFound('No issuer cert. found for '
                                         'certificate "%s"'%x509Cert2Verify.dn)
        
        # If this point is reached then an issuing cert is missing from the
        # chain        
        raise X509CertIssuerNotFound('Can\'t find issuer cert "%s" for '
                                     'certificate "%s"' %
                                     (x509Cert2Verify.issuer, 
                                      x509Cert2Verify.dn))


def X509StackParseFromDER(derString):
    """Make a new stack from a DER string
    
    @param derString: DER formatted X.509 stack data
    @type derString: string
    @return: new stack object
    @rtype: X509Stack""" 
    return X509Stack(m2X509Stack=M2Crypto.X509.new_stack_from_der(derString))


class X500DNError(Exception):
    """Exception handling for NDG X.500 DN class."""


# For use with parseSeparator method:
import re


class X500DN(dict):
    "NDG X500 Distinguished name"
    
    # Class attribute - look-up mapping short name attributes to their long
    # name equivalents
    # * private *
    __shortNameLUT = {
        'commonName':               'CN',
        'organisationalUnitName':   'OU',
        'organisation':             'O',
        'countryName':	    	    'C',
        'emailAddress':             'EMAILADDRESS',
        'localityName':	    	    'L',
        'stateOrProvinceName':	    'ST',
        'streetAddress':            'STREET',
        'domainComponent':	        'DC',
        'userid':	    	        'UID'
    }
    SLASH_PARSER_RE_STR = '/(%s)=' % '|'.join(__shortNameLUT.keys() + 
                                              __shortNameLUT.values())    
    SLASH_PARSER_RE = re.compile(SLASH_PARSER_RE_STR)

    COMMA_PARSER_RE_STR = '[,]?\s*(%s)=' % '|'.join(__shortNameLUT.keys() + 
                                                    __shortNameLUT.values())    
    COMMA_PARSER_RE = re.compile(COMMA_PARSER_RE_STR)
    
    def __init__(self, dn=None, m2CryptoX509Name=None, separator=None):

        """Create a new X500 Distinguished Name

        @type m2CryptoX509Name: M2Crypto.X509.X509_Name
        @param m2CryptoX509Name:   initialise using using an 
        M2Crypto.X509.X509_Name
        @type dn: basestring
        @param dn: initialise using a distinguished name string
        @type separator: basestring
        @param: separator: separator used to delimit dn fields - usually '/' 
        or ','.  If dn is input and separator is omitted the separator 
        character will be automatically parsed from the dn string.
        """
        
        # Private key data
        self.__dat = {}.fromkeys(X500DN.__shortNameLUT.values(), '')
    
        dict.__init__(self)
    
        self.__separator = None
        
        # Check for separator from input
      	if separator is not None:
            if not isinstance(separator, basestring):
                raise X500DNError("dn Separator must be a valid string")

            # Check for single character but allow trailing space chars
            if len(separator.lstrip()) is not 1:
                raise X500DNError("dn separator must be a single character")

            self.__separator = separator
	    
        if m2CryptoX509Name is not None:
            # the argument is an x509 dn in m2crypto format
            self.deserialise(str(m2CryptoX509Name))
            
        elif dn is not None:
            # Separator can be parsed from the input DN string - only attempt
            # if no explict separator was input
            if self.__separator is None:
                self.__separator = self.parseSeparator(dn)
                
            # Split Distinguished name string into constituent fields
            self.deserialise(dn)

    @classmethod
    def fromString(cls, dn):
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
        raise X500DNError('Keys cannot be deleted from the X500DN')

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
        raise X500DNError("Data cannot be cleared from X500DN")

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

            self.__separator = separator
            
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

            self.__separator = separator

        # If no separator has been set, parse if from the DN string            
        if self.__separator is None:
            self.__separator = self.parseSeparator(dn)

        if self.__separator == '/':
            parserRe = self.__class__.SLASH_PARSER_RE
            
        elif self.__separator == ',':
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
                if key not in self.__dat and key not in self.__shortNameLUT:
                    raise X500DNError('Invalid field "%s" in input DN string' %
                                      key)

                self.__dat[key] = val

                
        except Exception, excep:
            raise X500DNError("Error de-serialising DN \"%s\": %s" % \
                              (dn, str(excep)))

    deserialize = deserialise
    
    def parseSeparator(self, dn):
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
    def Parse(cls, dn):
        """Convenience method to create an X500DN object from a DN string
        @type dn: basestring
        @param dn: Distinguished Name 
        """
        return cls(dn=dn)
    
    Deserialise = Deserialize = Parse