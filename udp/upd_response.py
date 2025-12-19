import socket
# SERVER
# PORT AND IP

UDP_IP = '127.0.0.1'
UDP_PORT = 5005

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP IPv4
sock.bind((UDP_IP, UDP_PORT))

print(f'Listening for UDP packets on {UDP_IP}:{UDP_PORT}')
while True:
    data,addr = sock.recvfrom(4098)
    print(f'Recived packet from {addr}:{data.decode('utf-8')}')