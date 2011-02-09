'''ZSI ElementTree ElementProxy class an interface to ZSI's ElementProxy

Freely adapted from original by Joshua R. Boverhof, LBNL
'''
from ZSI.wstools.Namespaces import SCHEMA, XMLNS, SOAP
from ZSI.wstools.Utility import MessageInterface
from elementtree import ElementC14N, ElementTree
from StringIO import StringIO

from xml.dom import Node # Enable mimic of xml.dom behaviour


class ElementProxyException(Exception):
    ''''''

class ElementTreeProxy(MessageInterface):
    '''ElementTree wrapper
    TODO: issue with "getPrefix"
    '''
    _soap_env_prefix = 'SOAP-ENV'
    _soap_enc_prefix = 'SOAP-ENC'
    _soap_env_nsuri = SOAP.ENV
    _soap_enc_nsuri = SOAP.ENC

    def __init__(self, message=None, rootElem=None, elem=None, text=None):
        '''Initialize'''
        self._elem = elem
        self._rootElem = rootElem
        self._etree = None
        self._rootETree = None
        
        # Pseudo text node - it has a text attribute only
        self._text = text
        if text is not None and self._elem is not None:
            raise ValueError("elem keyword must not be set for a text node")
        
        # Flag to enable correct behaviour for DOM childNodes
        self._treeRootSet = False
        
        if isinstance(elem, ElementTree.Element):
            self._etree = ElementTree.ElementTree(element=elem)
        
        if isinstance(rootElem, ElementTree.Element):
            self._rootETree = ElementTree.ElementTree(element=rootElem)
            
        
    def __str__(self):
        return self.toString()
        
    def toString(self):
        return self.canonicalize()
    
    #############################################
    #Methods used in TypeCodes
    #############################################
    def createAppendElement(self, namespaceURI, localName, prefix=None):
        '''Create a new element (namespaceURI,name), append it
           to current node, and return the newly created node.
        Keyword arguments:
            namespaceURI -- namespace of element to create
            localName -- local name of new element
            prefix -- if namespaceURI is not defined, declare prefix.  defaults
                to 'ns1' if left unspecified.
        '''
        if not prefix:
            prefix = 'ns0'
            
        if namespaceURI:  
                      
            # Search for matching prefix
            matchingPrefix = None
            for elem in self._rootElem.getiterator():
                for k, v in elem.items():
                    if k.startswith("xmlns:") and v == namespaceURI:
                        # Namespace declaration found
                        matchingPrefix = k[6:]
                        matchingElem = elem
                        break

            newElem = ElementTree.Element("{%s}%s" % (namespaceURI, localName))

            if not matchingPrefix:
                matchingPrefix = prefix
                
                # No prefix found so add namespace declaration 
                newElem.set("xmlns:%s" % matchingPrefix, namespaceURI)
        else:
            assert prefix, "Prefix must be set - no namespaceURI was provided"
        
        self._elem.append(newElem)        
        eproxy = ElementTreeProxy(rootElem=self._rootElem, elem=newElem)

        return eproxy

    def createAppendTextNode(self, pyobj):
        '''TODO: obviously mixed text content cannot be accurately
        represented via this interface.  Only 1 possible text node/element
        '''
        self._elem.text = pyobj

    def createDocument(self, namespaceURI=SOAP.ENV, localName='Envelope'):

        prefix = self._soap_env_prefix

        self._elem = ElementTree.Element('{%s}%s' %(namespaceURI, localName))
        self._etree = ElementTree.ElementTree(element=self._elem)
        self._elem.set("xmlns:%s" % prefix, namespaceURI)
        self._rootElem = self._elem
        self._rootETree = self._etree
        
    def getElement(self, namespaceURI, localName):
        for e in self._elem.getiterator():
            l = e.tag.strip('{').split('}')
            if not namespaceURI:
                if len(l) == 1 and l[0] == localName:
                    eproxy = ElementTreeProxy(elem=e, etree=self._etree)
                    return eproxy
            elif len(l) == 2 and l[0] == namespaceURI and l[1] == localName:
                eproxy = ElementTreeProxy(elem=e, etree=self._etree)
                return eproxy
                
        raise ElementProxyException,\
            'No such element(%s,%s)' %(namespaceURI,localName)
        
    def getPrefix(self, namespaceURI):
        '''TODO: this is not possible w/elementTree since namespace prefix
        mappings aren't done until serialization.  completely abstracted out.
        '''
        raise NotImplementedError, "this func isn't going to work"
        
    def setAttributeNS(self, namespaceURI, localName, value):
        '''
        Keyword arguments:
            namespaceURI -- namespace of attribute to create, None is for
                attributes in no namespace.
            localName -- local name of new attribute
            value -- value of new attribute
        ''' 
        self._etree.attrib["{%s}%s" %(namespaceURI, localName)] = value

    def getAttributeNS(self, namespaceURI, localName):
        
        return self._elem.get('{%s}%s' % (namespaceURI, localName))
        
    def setAttributeType(self, namespaceURI, localName):
        '''xsi:type attribute, value must be a QName
        '''
        self.setAttributeNS(SCHEMA.XSI3, 'type', 
            ElementTree.QName('{%s}%s' %(namespaceURI,localName))
        )
        
    def setNamespaceAttribute(self, prefix, namespaceURI):
        '''TODO: Not sure how to force this to be used by ElementTree
        Keyword arguments:
            prefix -- xmlns prefix
            namespaceURI -- value of prefix
        '''
        #self._etree.attrib["xmlns:%s" %prefix] = namespaceURI
        self._elem.set("xmlns:%s" % prefix, namespaceURI)
        
    def canonicalize(self, **kw):
        '''Canonicalize using ElementC14N.write - see ElementC14N for details
        of keyword options'''
        
        f = StringIO()

        # Check that namespace scope has been added - this will be the case
        # for a parsed message but not true for a document created in memory.
        # In the latter case a call to build the scope is required
        if hasattr(self._rootETree, '_scope'):
            ElementC14N.write(self._rootETree, f, **kw)
        else:
            ElementC14N.write(ElementC14N.build_scoped_tree(self._rootElem),
                              f,
                              **kw)
            
        c14n = f.getvalue()

        return c14n

    
    def evaluate(self, expression, processorNss=None):
        elemList = self._etree.findall(expression, namespaces=processorNss)
            
        return [ElementTreeProxy(elem=elem, etree=self._etree) \
                for elem in elemList]
    
    # Methods to satisfy ParsedSoap interface        
    def fromString(self, input):
        '''Required by ParsedSoap to parse a string'''
        
        # Use ElementC14N.parse as fromstring doesn't create a scope dict
#        self._elem = ElementTree.fromstring(input)
#        self._etree = ElementTree.ElementTree(self._elem)
        fInput = StringIO()
        fInput.write(input)
        fInput.seek(0)
        
        self._rootETree = ElementC14N.parse(fInput)
        self._rootElem = self._rootETree.getroot()
        
        self._etree = self._rootETree
        self._elem = self._rootElem
        
        # Enables behaviour to mimic DOM interface - See _getChildNodes
        self._treeRootSet = True

        return self
    
    def _getChildNodes(self):
        '''childNodes property required by ParsedSoap'''
        if self._elem is None:
            return []
        
        # Check for top of tree
        if self._treeRootSet: 
            # Return a copy of the top level element with _treeRoot set to 
            # False so that the next time this method is called the children of
            # the top level element will be returned instead
            return [ElementTreeProxy(elem=self._elem, rootElem=self._rootElem)]
        elif self._elem is None:
            # A text node
            return []
        else:
            etProxyList=[ElementTreeProxy(elem=elem, rootElem=self._rootElem) \
                         for elem in list(self._elem)]
            
            # DOM treats text as a separate element - if text is set make a
            # new ElementProxy instance and append it to the list to be 
            # returned
            if self._elem.text is not None:
                etProxyList += [ElementTreeProxy(text=self._elem.text, 
                                                 rootElem=self._rootElem)]
                
            return etProxyList
          
    childNodes = property(fget=_getChildNodes)

    def _getNodeValue(self):
        '''Mimic nodeValue attribute of DOM interface'''
        return unicode(self._text)        
        
    nodeValue = property(fget=_getNodeValue)
    
    def _getNodeType(self):
        '''Minimal implementation to mimic behaviour of xml.dom.Node for 
        ParsedSoap interface'''
        if self._text is not None:
            return Node.TEXT_NODE
        else:
            return Node.ELEMENT_NODE
    
    nodeType = property(fget=_getNodeType)
    
    def _getLocalName(self):
        '''Parse localName from element tag of form {NS}localName'''
        return unicode(self._elem.tag.split('}')[-1])
    
    localName = property(fget=_getLocalName)
    
    def _getNamespaceURI(self):
        '''Parse NS from element tag of form {NS}localName'''
        return unicode(self._elem.tag.replace('{','').split('}')[0])
    
    namespaceURI = property(fget=_getNamespaceURI)
    
    def _getAttributes(self):
        '''Mimic attributes DOM attribute but note XML namespace declarations
        are not included in ET
        
        TODO: fix prefix - possible with _scope look-up, NamedNodeMap is not
        used - dict is used as an approximation'''
        namedNodeMap = {}

        if self._elem is None:
            return namedNodeMap
        
        prefix = u''
        for k, v in self._elem.attrib.items():
            localName = self.localName
            qName = prefix + u':' + localName
            nameNodeMap[qName] = Attr(qName, 
                                      namespaceURI=self.namespaceURI,
                                      localName=localName)
        return namedNodeMap
    
    attributes = property(fget=_getAttributes)

from copy import deepcopy

def _build_scoped_tree(elem):
    
    # Make a copy because attributes are to be deleted.
#    elem = deepcopy(_elem)
#    
#    # Deep copy misses out 'attrib' Element attribute
#    for e, _e in zip(elem.getiterator(), _elem.getiterator()):
#        if e.tag != _e.tag:
#            raise AttributeError("Tags don't match")
#        e.attrib = _e.attrib.copy()
#        
        
    root = ElementTree.ElementTree(elem)

    # build scope map
    root._scope = {}
    for e in elem.getiterator():
        scope = []
        for k in e.keys():
            if k.startswith("xmlns:"):
                # move xmlns prefix to scope map
                scope.append((k[6:], e.get(k)))
                #del e.attrib[k]
        if scope:
            root._scope[e] = scope
    # build parent map
    root._parent = dict((c, p) for p in elem.getiterator() for c in p)

    return root
