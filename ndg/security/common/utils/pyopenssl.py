"""PyOpenSSL utilites including HTTPSSocket class which wraps PyOpenSSL
SSL connection into a httplib-like interface suitable for use with urllib2

NERC DataGrid Security"""
__author__ = "P J Kershaw"
__date__ = "21/12/10"
__copyright__ = "(C) 2011 Science and Technology Facilities Council"
__license__ = "BSD - see LICENSE file in top-level directory"
__contact__ = "Philip.Kershaw@stfc.ac.uk"
__revision__ = '$Id$'
import logging
log = logging.getLogger(__name__)

from datetime import datetime
import socket

from cStringIO import StringIO
from httplib import HTTPConnection, HTTPS_PORT 
from urllib import addinfourl
from urllib2 import (OpenerDirector, AbstractHTTPHandler, URLError,
                     ProxyHandler, UnknownHandler, HTTPHandler,
                     HTTPDefaultErrorHandler, HTTPRedirectHandler,
                     FTPHandler, FileHandler, HTTPErrorProcessor)

from OpenSSL import SSL


class Socket(object):
    """SSL Socket class wraps pyOpenSSL's SSL.Connection class implementing
    the makefile method so that it is compatible with the standard socket
    interface and usable with httplib - see HTTPSConnection also in this 
    module
    
    @cvar default_buf_size: default buffer size for recv operations in the 
    makefile method
    @type default_buf_size: int
    """
    default_buf_size = 8192
    
    def __init__(self, ctx, sock=None):
        """Create SSL socket object
        
        @param ctx: SSL context
        @type ctx: OpenSSL.SSL.Context
        @param sock: underlying socket object
        @type sock: socket.socket
        """
        if sock is not None:    
            self.socket = sock
        else:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        self.__ssl_conn = SSL.Connection(ctx, self.socket)
        self.buf_size = self.__class__.default_buf_size

    def __del__(self):
        """Close underlying socket when this object goes out of scope
        """
        self.close()

    @property
    def buf_size(self):
        """Buffer size for makefile method recv() operations"""
        return self.__buf_size
    
    @buf_size.setter
    def buf_size(self, value):
        """Buffer size for makefile method recv() operations"""
        if not isinstance(value, (int, long)):
            raise TypeError('Expecting int or long type for "buf_size"; '
                            'got %r instead' % type(value))
        self.__buf_size = value
            
    def close(self):
        """Shutdown the SSL connection and call the close method of the 
        underlying socket"""
        self.__ssl_conn.shutdown()
        self.__ssl_conn.close()

    def set_shutdown(self, mode):
        """Set the shutdown state of the Connection. 
        @param mode: bit vector of either or both of SENT_SHUTDOWN and 
        RECEIVED_SHUTDOWN
        """
        self.__ssl_conn.set_shutdown(mode)

    def get_shutdown(self):
        """Get the shutdown state of the Connection. 
        @return: bit vector of either or both of SENT_SHUTDOWN and 
        RECEIVED_SHUTDOWN
        """
        return self.__ssl_conn.get_shutdown()

    def bind(self, addr):
        """bind to the given address - calls method of the underlying socket
        @param addr: address/port number tuple 
        @type addr: tuple"""
        self.__ssl_conn.bind(addr)

    def listen(self, backlog):
        """Listen for connections made to the socket. 

        @param backlog: specifies the maximum number of queued connections and 
        should be at least 1; the maximum value is system-dependent (usually 5).
        @param backlog: int
        """
        self.__ssl_conn.listen(backlog)    

    def set_accept_state(self):
        """Set the connection to work in server mode. The handshake will be 
        handled automatically by read/write"""
        self.__ssl_conn.set_accept_state()

    def accept(self):
        """Accept an SSL connection. 
        
        @return: pair (ssl, addr) where ssl is a new SSL connection object and 
        addr is the address bound to the other end of the SSL connection.
        @rtype: tuple
        """
        return self.__ssl_conn.accept()

    def set_connect_state(self):
        """Set the connection to work in client mode. The handshake will be 
        handled automatically by read/write"""
        self.__ssl_conn.set_connect_state()

    def connect(self, addr):
        """Call the connect method of the underlying socket and set up SSL on 
        the socket, using the Context object supplied to this Connection object 
        at creation. 
        
        @param addr: address/port number pair
        @type addr: tuple
        """
        self.__ssl_conn.connect(addr)

    def shutdown(self, how):
        """Send the shutdown message to the Connection. 

        @param how: for socket.socket this flag determines whether read, write
        or both type operations are supported.  OpenSSL.SSL.Connection doesn't
        support this so this parameter is IGNORED
        @return: true if the shutdown message exchange is completed and false 
        otherwise (in which case you call recv() or send() when the connection 
        becomes readable/writeable. 
        @rtype: bool
        """
        return self.__ssl_conn.shutdown()

    def renegotiate(self):
        """Renegotiate this connection's SSL parameters."""
        return self.__ssl_conn.renegotiate()

    def pending(self):
        """@return: numbers of bytes that can be safely read from the SSL 
        buffer.
        @rtype: int
        """
        return self.__ssl_conn.pending()
    
    def send(self, data, *flags_arg):
        """Send data to the socket. Nb. The optional flags argument is ignored.
        - retained for compatibility with socket.socket interface
        
        @param data: data to send down the socket
        @type data: string 
        """
        return self.__ssl_conn.send(data)
        
    def sendall(self, data):
        self.__ssl_conn.sendall(data)
        
    def recv(self, size=default_buf_size):
        """Receive data from the Connection. 
        
        @param size: The maximum amount of data to be received at once
        @type size: int
        @return: data received. 
        @rtype: string
        """
        return self.__ssl_conn.recv(size)

    def setblocking(self, mode):
        """Set this connection's underlying socket blocking _mode_.
        
        @param mode: blocking mode
        @type mode: int
        """
        self.__ssl_conn.setblocking(mode)

    def fileno(self):
        """
        @return: file descriptor number for the underlying socket
        @rtype: int
        """ 
        return self.__ssl_conn.fileno()

    def getsockopt(self, *args):
        """See socket.socket.getsockopt
        """
        return self.__ssl_conn.getsockopt(*args)

    def setsockopt(self, *args):
        """See socket.socket.setsockopt
        
        @return: value of the given socket option  
        @rtype: int/string
        """        
        return self.__ssl_conn.setsockopt(*args)

    def state_string(self):
        """Return the SSL state of this connection."""
        return self.__ssl_conn.state_string()

    def makefile(self, *args):
        """Specific to Python socket API and required by httplib: convert
        response into a file-like object.  This implementation reads using recv
        and copies the output into a StringIO buffer to simulate a file object
        for consumption by httplib
        
        Nb. Ignoring optional file open mode (StringIO is generic and will
        open for read and write unless a string is passed to the constructor)
        and buffer size - httplib set a zero buffer size which results in recv
        reading nothing
        
        @return: file object for data returned from socket
        @rtype: cStringIO.StringO
        """
        # Optimisation
        _buf_size = self.buf_size
        
        i=0
        stream = StringIO()
        startTime = datetime.utcnow()
        try:
            dat = self.__ssl_conn.recv(_buf_size)
            while dat:
                i+=1
                stream.write(dat)
                dat = self.__ssl_conn.recv(_buf_size)
                
        except (SSL.ZeroReturnError, SSL.SysCallError):
            # Connection is closed - assuming here that all is well and full
            # response has been received.  httplib will catch an error in
            # incomplete content since it checks the content-length header 
            # against the actual length of data received 
            pass
        
        if log.getEffectiveLevel() <= logging.DEBUG:
            log.debug("Socket.makefile %d recv calls completed in %s", i, 
                      datetime.utcnow() - startTime)

        # Make sure to rewind the buffer otherwise consumers of the content will
        # read from the end of the buffer
        stream.seek(0)
        
        return stream

    def getsockname(self):
        """
        @return: the socket's own address
        @rtype:
        """
        return self.__ssl_conn.getsockname()

    def getpeername(self):
        """
        @return: remote address to which the socket is connected
        """
        return self.__ssl_conn.getpeername()
    
    def get_context(self):
        '''Retrieve the Context object associated with this Connection. '''
        return self.__ssl_conn.get_context()
    
    def get_peer_certificate(self):
        '''Retrieve the other side's certificate (if any)  '''       
        return self.__ssl_conn.get_peer_certificate()
    

class HTTPSConnection(HTTPConnection):
    """This class allows communication via SSL using PyOpenSSL.
    @cvar default_port: default port for this class (443)
    @type default_port: int
    """

    default_port = HTTPS_PORT

    def __init__(self, host, port=None, strict=None, ssl_context=None):
        """@param host: hostname to connect to
        @type host: string
        @param port: port number for host
        @type port: int 
        @param strict: If true, raise BadStatusLine if the status line can't be
        parsed as a valid HTTP/1.0 or 1.1 status line.  By default it is
        false because it prevents clients from talking to HTTP/0.9
        servers.
        @type strict: int
        @param ssl_context: SSL Context object
        @type ssl_context: OpenSSL.SSL.Context
        """
        if ssl_context is None:
            self.ssl_ctx = SSL.Context(SSL.SSLv23_METHOD)
        else:
            if not isinstance(ssl_context, SSL.Context):
                raise TypeError('Expecting OpenSSL.SSL.Context type for '
                                '"ssl_context" keyword; got %r' % 
                                type(ssl_context))
            self.ssl_ctx = ssl_context
            
        HTTPConnection.__init__(self, host, port, strict)

    def connect(self):
        """Create SSL socket and connect to peer
        """
        self.sock = Socket(self.ssl_ctx, socket.socket())
        self.sock.connect((self.host, self.port))

    def close(self):
        """Close socket and shutdown SSL connection"""
        self.sock.close()
        
        
class HTTPSHandler(AbstractHTTPHandler):
    """PyOpenSSL based HTTPS Handler class to fit urllib2's handler interface"""
    
    def __init__(self, ssl_context=None):
        """@param ssl_context: SSL context
        @type ssl_context: OpenSSL.SSL.Context
        """
        AbstractHTTPHandler.__init__(self)

        if ssl_context is not None:
            if not isinstance(ssl_context, SSL.Context):
                raise TypeError('Expecting OpenSSL.SSL.Context type for "'
                                'ssl_context" keyword; got %r instead' %
                                ssl_context)
            self.ctx = ssl_context
        else:
            self.ctx = SSL.Context(SSL.SSLv23_METHOD)

    def https_open(self, req):
        """Return an addinfourl object for the request, using http_class.

        http_class must implement the HTTPConnection API from httplib.
        The addinfourl return value is a file-like object.  It also
        has methods and attributes including:
            - info(): return a mimetools.Message object for the headers
            - geturl(): return the original request URL
            - code: HTTP status code
        """
        host = req.get_host()
        if not host:
            raise URLError('no host given')

        # TODO: Add HTTPS Proxy support here
        h = HTTPSConnection(host=host, ssl_context=self.ctx)
        h.set_debuglevel(self._debuglevel)

        headers = dict(req.headers)
        headers.update(req.unredirected_hdrs)
        
        # We want to make an HTTP/1.1 request, but the addinfourl
        # class isn't prepared to deal with a persistent connection.
        # It will try to read all remaining data from the socket,
        # which will block while the server waits for the next request.
        # So make sure the connection gets closed after the (only)
        # request.
        headers["Connection"] = "close"
        try:
            h.request(req.get_method(), req.get_selector(), req.data, headers)
            r = h.getresponse()
        except socket.error, err: # XXX what error?
            raise URLError(err)

        # Pick apart the HTTPResponse object to get the addinfourl
        # object initialized properly.

        # Wrap the HTTPResponse object in socket's file object adapter
        # for Windows.  That adapter calls recv(), so delegate recv()
        # to read().  This weird wrapping allows the returned object to
        # have readline() and readlines() methods.

        # XXX It might be better to extract the read buffering code
        # out of socket._fileobject() and into a base class.

        r.recv = r.read
        fp = socket._fileobject(r, close=True)

        resp = addinfourl(fp, r.msg, req.get_full_url())
        resp.code = r.status
        resp.msg = r.reason
        return resp

    https_request = AbstractHTTPHandler.do_request_


# Copied from urllib2 with modifications for ssl
def urllib2_build_opener(ssl_context=None, *handlers):
    """Create an opener object from a list of handlers.

    The opener will use several default handlers, including support
    for HTTP and FTP.

    If any of the handlers passed as arguments are subclasses of the
    default handlers, the default handlers will not be used.
    """
    import types
    def isclass(obj):
        return isinstance(obj, types.ClassType) or hasattr(obj, "__bases__")

    opener = OpenerDirector()
    default_classes = [ProxyHandler, UnknownHandler, HTTPHandler,
                       HTTPDefaultErrorHandler, HTTPRedirectHandler,
                       FTPHandler, FileHandler, HTTPErrorProcessor]
    skip = []
    for klass in default_classes:
        for check in handlers:
            if isclass(check):
                if issubclass(check, klass):
                    skip.append(klass)
            elif isinstance(check, klass):
                skip.append(klass)
    for klass in skip:
        default_classes.remove(klass)

    for klass in default_classes:
        opener.add_handler(klass())

    # Add the HTTPS handler with ssl_context
    if HTTPSHandler not in skip:
        opener.add_handler(HTTPSHandler(ssl_context))

    for h in handlers:
        if isclass(h):
            h = h()
        opener.add_handler(h)
        
    return opener
