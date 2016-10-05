import socket
from Networks.Security_connections.Client import Client
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import _thread as thread
import ssl
from tkinter import *
import json
import crypt
import base64

client=None

class AESKey():
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv


class RSAKey():
    def __init__(self, pub, priv):
        self.public = pub
        self.private = priv



def recv():
    while True:
        message = client.read().decode()
        if message:
            print(message)
            #encode_data=json.loads((message).decode())
            log.insert(END,message+'\n')
            #log.insert(END, '%s:(%s):%s\n'%(encode_data['source'],encode_data['username'],encode_data['data']))
            log.see(END)
    thread.exit_thread()
def sendproc(event):
    data={
        'source':[HOST,PORT],
        'username':name.get(),
        'data':text.get()
    }
    #encode=json.dumps(data).encode()
    #print(encode)
    message=text.get()
    log.insert(END,'Me: %s\n'%text.get())
    client.write(message.encode())
    text.set('')

def do_handshake(comm):
    #RSA handshake
    rsa_encode=comm.recv(4096)
    rsa_key=base64.b64decode(rsa_encode)

    key=RSA.generate(2048)

    my_rsa_kay=base64.b64encode(key.publickey().exportKey())
    comm.send(my_rsa_kay)

    #Gather AES key
    cipher = PKCS1_OAEP.new(key)
    encode_encrypt=base64.b64decode(comm.recv(4096))
    decrypt=cipher.decrypt(encode_encrypt)
    aes_key_encode=base64.b64decode(decrypt)
    key=aes_key_encode[AES.block_size:]
    iv = aes_key_encode[:AES.block_size]

    return Client(comm,AESKey(key,iv))



HOST='0.0.0.0'
PORT=1200




if __name__ == '__main__':
    tk = Tk()
    tk.title('MegaChat')
    tk.geometry('400x300')
    text = StringVar()
    name = StringVar()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    # connstream=ssl.wrap_socket(sock)
    sock.connect((HOST, PORT))
    client = do_handshake(sock)


    text.set('')
    name.set('HabrUser')

    log = Text(tk)
    nick = Entry(tk, textvariable=name)
    msg = Entry(tk, textvariable=text)
    msg.pack(side='bottom', fill='x', expand='true')
    nick.pack(side='bottom', fill='x', expand='true')
    log.pack(side='top', fill='x', expand='true')

    msg.bind('<Return>', sendproc)
    msg.focus_set()
    thread.start_new_thread(recv, ())
    tk.mainloop()
