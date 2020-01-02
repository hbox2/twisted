from OpenSSL import SSL
from twisted.internet import reactor, ssl
from twisted.internet.protocol import ClientFactory
from twisted.protocols.basic import LineReceiver
from file_md5 import validate_file_md5_hash

class ClientTLSContext(ssl.ClientContextFactory):
    isClient = 1
    def getContext(self):
        return SSL.Context(SSL.TLSv1_2_METHOD)

class TLSClient(LineReceiver):
    pretext = [
        "first line",
        "last thing before TLS starts",
        "STARTTLS"]

    posttext = [
        "first thing in TLS",
        "last thing ever"]

    def connectionMade(self):
        self.file_handler = None
        for l in self.pretext:
            self.sendLine(l.encode('utf8'))
        self.sendLine("get".encode('utf8'))


    def lineReceived(self, line):
        line = line.decode('utf-8')
        print("received: " + line)

        if line == "READY":
            ctx = ClientTLSContext()
            self.transport.startTLS(ctx, self.factory)
            print("Start TLS")
            for l in self.posttext:
                self.sendLine(l.encode('utf-8'))
            self.setRawMode()

        if line[0:5] == "hash:":
            hash_file = line[5:]
            validate_file_md5_hash('Mail-received', hash_file)
            self.transport.loseConnection()


    def rawDataReceived(self, data):
        if not self.file_handler:
            self.file_handler = open("Mail-received", 'wb')

        if data.endswith(b'\r\n'):
            print ("File received")
            data = data[:-2]
            self.file_handler.write(data)
            self.setLineMode()

            self.file_handler.close()
            self.file_handler = None

        else:
            self.file_handler.write(data)

class TLSClientFactory(ClientFactory):
    protocol = TLSClient
    def clientConnectionFailed(self, connector, reason):
        print ("CONNection FAILed: ", reason.getErrorMessage())
        reactor.stop()

    def clientConnectionLost(self, connector, reason):
        print ("CONNection LOST: ", reason.getErrorMessage())
        reactor.stop()

if __name__ == "__main__":
    factory = TLSClientFactory()
    reactor.connectTCP('localhost', 8000, factory)
    reactor.run()
