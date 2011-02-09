"""Policy Information Point Package containing various PIP implementations.  
The PIP is a helper to the PDP providing information to enable it to make access
control decisions

NERC DataGrid Project
"""
__author__ = "P J Kershaw"
__date__ = "19/02/10"
__copyright__ = "(C) 2009 Science and Technology Facilities Council"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = "$Id$"
from ndg.security.common.authz import _AttrDict, Subject


class PIPAttributeQuery(_AttrDict):
    '''Policy Information Point Query class.'''
    namespaces = (
        "urn:ndg:security:authz:1.0:attr:subject",
        "urn:ndg:security:authz:1.0:attr:attributeAuthorityURI",
    )  
    (SUBJECT_NS, ATTRIBUTEAUTHORITY_NS) = namespaces    


class PIPAttributeResponse(dict):
    '''Policy Information Point Response class.'''
    namespaces = (
        Subject.ROLES_NS,
    )
    

class PIPBase(object):
    """Policy Information Point base class.  PIP enables PDP to get user 
    attribute information in order to make access control decisions 
    """
    __slots__ = ()
    
    def __init__(self, prefix='', **cfg):
        '''Initialise settings for connection to an Attribute Authority'''
        raise NotImplementedError(PIPBase.__init__.__doc__)
    
    def attributeQuery(self, attributeQuery):
        """Query the Attribute Authority specified in the request to retrieve
        the attributes if any corresponding to the subject
        
        @type attributeResponse: PIPAttributeQuery
        @param attributeResponse: 
        @rtype: PIPAttributeResponse
        @return: response containing the attributes retrieved from the
        Attribute Authority"""
        raise NotImplementedError(PIPBase.attributeQuery.__doc__)