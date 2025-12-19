import socket
import time

UDP_IP = '127.0.0.1'
UDP_PORT = 5005
message = 'Hello UDP'
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP IPv4
for i in range(10):
    sock.sendto(message.encode(), (UDP_IP, UDP_PORT))
    print(f'Sent UDP pakcet to {UDP_PORT}: {UDP_PORT}')
    time.sleep(3)

sock.close()
