import base64
from Crypto.Cipher import AES

class Client():
    ack=b'acknowledgement'

    def __init__(self, comm, key):
        self.comm = comm
        self._cipher=AES.new(key.key,AES.MODE_CFB,key.iv)
        #self._is_writeble=True

    def write(self, data):
        #if not self._is_writeble and self.readAck() :
        #    raise ValueError('Ack is incorrect')
        encrypt=self._cipher.encrypt(data)
        encode_encrypt=base64.b64encode(encrypt)
        self.comm.send(encode_encrypt)
        #self._is_writeble=False
        #self.sendAck()

    def read(self):
        data=self.comm.recv(4096)
        decode=base64.b64decode(data)
        decrypt=self._cipher.decrypt(decode)
        #self.sendAck()
        return decrypt

    def sendAck(self):
        self.write(self.ack)

    def readAck(self):
        ack = self.read()
        if ack != ack:
            return False
        return True



    def __del__(self):
        self.comm.close()
