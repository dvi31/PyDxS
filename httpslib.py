"""HTTPS Transport for suds SOAP client using certificate and key files."""

# Std.
import urllib2, socket, ssl, pprint


# Suds.
from httplib import HTTPSConnection
from suds.transport.http import HttpTransport


class HTTPSClientAuthHandler(urllib2.HTTPSHandler):
    def __init__(self, key, cert, cacert):
        urllib2.HTTPSHandler.__init__(self)
        self.key = key
        self.cert = cert
        self.cacert = cacert
        self.peercert = None

    def https_open(self, req):
        # Rather than pass in a reference to a connection class, we pass in
        # a reference to a function which, for all intents and purposes,
        # will behave as a constructor
        result = self.do_open(self.getConnection, req)
        return result

    def getConnection(self, host, timeout=300):
        self.context = ssl._create_default_https_context(cafile=self.cacert)
        # self.context.set_servername_callback(cb_sni)
        self.context.load_cert_chain(self.cert, self.key)
        self.context.verify_mode = ssl.CERT_REQUIRED

        self.con = MyHTTPSConnection(host, context=self.context, handler=self)
        return self.con

    def setpeercert(self, cert):
        if self.peercert is not None and self.peercert != cert:
            raise Exception('peercert', 'peercert has changed')
        else:
            self.peercert = cert

    def getpeercert(self):
        return self.peercert


class MyHTTPSConnection(HTTPSConnection):
    def __init__(self, host, port=None, key_file=None, cert_file=None,
                 strict=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                 source_address=None, context=None, handler=None):
        HTTPSConnection.__init__(self, host, port=port, key_file=key_file, cert_file=cert_file,
                                 strict=strict, timeout=timeout,
                                 source_address=source_address, context=context)

        self.handler = handler

    def connect(self):
        "Connect to a host on a given (SSL) port."
        HTTPSConnection.connect(self)
        self.handler.setpeercert(self.sock.getpeercert(False))

    def getpeercert(self):
        return self.peercert


class HTTPSClientCertTransport(HttpTransport):
    def __init__(self, key, cert, cacert, *args, **kwargs):
        HttpTransport.__init__(self, *args, **kwargs)
        self.key = key
        self.cert = cert
        self.cacert = cacert

    def u2open(self, u2request):
        """
        Open a connection.
        @param u2request: A urllib2 request.
        @type u2request: urllib2.Requet.
        @return: The opened file-like urllib2 object.
        @rtype: fp
        """
        tm = self.options.timeout
        self.handler = HTTPSClientAuthHandler(self.key, self.cert, self.cacert)
        url = urllib2.build_opener(self.handler)
        if self.u2ver() < 2.6:
            socket.setdefaulttimeout(tm)
            return url.open(u2request)
        else:
            return url.open(u2request, timeout=tm)

    def getpeercert(self):
        return self.handler.getpeercert()
