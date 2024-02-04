import os
import paramiko
import socketserver
import threading
import base64
import time

os.system("ssh-keygen -f hostkey -N ''")
host_key = paramiko.RSAKey(filename="hostkey")
yaonet_key = paramiko.ECDSAKey(
    data=base64.b64decode(open("id_ecdsa.pub").read().split(" ")[1])
)

with open("flag.txt") as f:
    flag = f.read().strip()

class Server (paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()
    
    def get_allowed_auths(self, username): 
        return "publickey"

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_publickey(self, username, key):
        if username == "yaonet" and key == yaonet_key:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        return True

class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        session = paramiko.Transport(self.request)
        session.add_server_key(host_key)
        session.start_server(server=Server())

        channel = session.accept(20)

        if not channel:
            return

        stdio = channel.makefile("rwU")
        stdio.write(flag + "\r\n")
        time.sleep(1)

        channel.close()
        session.close()

socketserver.ThreadingTCPServer.allow_reuse_address = True
if __name__ == "__main__":
    with socketserver.ThreadingTCPServer(("0.0.0.0", 22), MyTCPHandler) as server:
        server.serve_forever()
