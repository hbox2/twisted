from OpenSSL import SSL
import twisted
from twisted.internet import reactor, ssl, protocol
from twisted.internet.protocol import ServerFactory
from twisted.protocols.basic import LineReceiver
from twisted.protocols import basic
from file_md5 import *

class TLSServer(LineReceiver):
    def lineReceived(self, line):
        line = line.decode('utf-8')
        print ("received: " + line)

        if line == "STARTTLS":
            print ("-- Switching to TLS")
            self.sendLine('READY'.encode('utf-8'))
            ctx = ServerTLSContext(privateKeyFileName='keys/server.key',certificateFileName='keys/server.crt',sslmethod = SSL.TLSv1_2_METHOD,)
            self.transport.startTLS(ctx, self.factory)

        if line == "get":
            print("Transfer file")
            self.setRawMode()
            for bytes in read_bytes_from_file('Mail'):
                self.transport.write(b'bytes')
            self.transport.write(b'\r\n')
            self.setLineMode()
            md5 = get_file_md5_hash('Mail')
            print(md5)
            self.sendLine("hash:".encode('utf-8') + md5.encode('utf-8'))


class ServerTLSContext(ssl.DefaultOpenSSLContextFactory):
    def __init__(self, *args, **kw):
        kw['sslmethod'] = SSL.TLSv1_2_METHOD
        SSL.Context(SSL.SSLv23_METHOD).set_options(SSL.OP_NO_SSLv2 |  SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 |  SSL.OP_NO_TLSv1_1)
        ssl.DefaultOpenSSLContextFactory.__init__(self, *args, **kw)

if __name__ == '__main__':

    factory = ServerFactory()
    factory.protocol = TLSServer
    reactor.listenTCP(8000, factory)
    print("Listening ...")
    reactor.run()
