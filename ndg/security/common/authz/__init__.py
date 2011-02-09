"""NDG Security authorisation package - contains code for Gatekeeper (PEP)
and authorisation interfaces (PDP)

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "04/04/08"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
 
       
class _AttrDict(dict):
    """Utility class for holding a constrained list of attributes governed
    by a namespace list"""
    namespaces = ()
    def __init__(self, **attributes):
        invalidAttributes = [attr for attr in attributes
                             if attr not in self.__class__.namespaces]
        if len(invalidAttributes) > 0:
            raise TypeError("The following attribute namespace(s) are not "
                            "recognised: %s" % invalidAttributes)
            
        self.update(attributes)

    def __setitem__(self, key, val):
        if key not in self.__class__.namespaces:
            raise KeyError('Namespace %r not recognised.  Valid namespaces '
                           'are: %r' % (key, self.__class__.namespaces))
            
        dict.__setitem__(self, key, val)


    def update(self, d, **kw):        
        for dictArg in (d, kw):
            for k in dictArg:
                if k not in self.__class__.namespaces:
                    raise KeyError('Namespace "%s" not recognised.  Valid '
                                   'namespaces are: %s' % 
                                   self.__class__.namespaces)
        
        dict.update(self, d, **kw)
 
    
class SubjectRetrievalError(Exception):
    """Generic exception class for errors related to information about the
    subject"""       
       
        
class SubjectBase(_AttrDict):
    '''Base class Subject designator'''
    namespaces = (
        "urn:ndg:security:authz:1.0:attr:subject:userId",
        "urn:ndg:security:authz:1.0:attr:subject:roles", 
    )
    (USERID_NS, ROLES_NS,) = namespaces


class Subject(SubjectBase):
    """Container for information about the subject of the query"""