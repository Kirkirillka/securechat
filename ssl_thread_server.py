
import socket,time,_thread as thread,ssl
import json
import base64
from Client import Client
HOST='0.0.0.0'
PORT=1200


RSA_ACK=b'RSA_ACK:)'
RSA_FIN=b'RSA_FIN'
AES_ACK=b'AES_ACK:>)'
AES_FIN=b'RSA_FIN'

import Crypto
from Crypto.Cipher import PKCS1_OAEP,AES
from Crypto.PublicKey import RSA
from Crypto import Random


class SecureThreadServer():
    def __init__(self,host,port):
        self.socket=socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.socket.bind((host,port))
        self.socket.listen(100)
        self.clients=[]
        self.mutex=thread.allocate_lock()

    class AESKey():
        def __init__(self,key,iv):
            self.key=key
            self.iv=iv

    class RSAKey():
        def __init__(self,pub,priv):
            self.public=pub
            self.private=priv

    def do_handshake(self,comm):
        random_generator=Random.new().read
        rsa_key=RSA.generate(2048)
        s=self.send_rsa_key(comm,rsa_key)
        if isinstance(s,bool) and not s:
            return False

        IV=Random.new().read(AES.block_size)
        key=Random.new().read(AES.key_size[2])

        #cipher = Crypto.Cipher.PKCS1_OAEP.new(rsa_key)
        the_other=Crypto.Cipher.PKCS1_OAEP.new(RSA.importKey(s))
        if not self.send_aes_key(comm,IV,key,the_other): return False

        return self.AESKey(key,IV)


    def send_rsa_key(self,comm,key):
        rsa_key=base64.b64encode(key.publickey().exportKey())
        #print(base64.b64decode(rsa_key))
        #print(rsa_key)
        try:
            comm.send(rsa_key)
            #if comm.recv(4096) != RSA_ACK:
            #    return False
            rsa_pub_other_client=comm.recv(4096)
            return base64.b64decode(rsa_pub_other_client)
        except Exception as x:
            print(x)
            return False

    def send_aes_key(self,comm,iv,key,RSA_cipher):
        if not RSA_cipher.can_encrypt():
            raise AttributeError('Cannot encrypt!')
        aes_key=base64.b64encode(iv+ key)

        try:
            encrypt=RSA_cipher.encrypt(aes_key)
            encode=base64.b64encode(encrypt)
            comm.send(encode)
            return True
            #return True if comm.recv(4096)==AES_ACK else False
        except Exception as x:
            print(x)
            return False

    def start_negotiation(self,commstream,addr):

            aes_key=self.do_handshake(commstream)
            if isinstance(aes_key,bool) and not aes_key:
                commstream.close()
                return

            new_client=Client(commstream,aes_key)
            self.clients.append(new_client)
            try:
                data=new_client.read()
                print(data)
                while data:
                    self.mutex.acquire()
                    for client in self.clients:
                        if client.comm is not commstream:
                            client.write(data)
                    self.mutex.release()
                    data=new_client.read()
            except Exception as x:
                print(x)
                self.clients.remove(new_client)
            finally:
                thread.exit_thread()

    def broadcast(self,message):
        for client in self.clients:
                    self.send(client,message)


    def send(self,client,message,source='server',username='admin'):
        payload = {
            'source': source,
            'username':username,
            'data':message
        }
        print(payload)
        client.write(json.dumps(payload).encode())

    def recv(self,commstream,size):
        return commstream.read(size).decode()

    def start_serve(self):
        while True:
            conn,addr=self.socket.accept()
            connstream=conn
            try:
                #connstream=ssl.wrap_socket(conn,keyfile='server.key',certfile='server.crt',server_side=True)
                pass
            except ssl.SSLError:
                print('Addr {} haven\' certificate!'.format(addr[0]))
                conn.close()
                continue
            print('%s is connected'%repr(addr))
            self.broadcast('%s is connected'%repr(addr))
            thread.start_new_thread(self.start_negotiation,(connstream,addr))


server=SecureThreadServer(HOST,PORT)
server.start_serve()
input()