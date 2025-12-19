import socket

PORT = 65435
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # connectare
    s.connect(('localhost', PORT))
    s.sendall(b'Hello World')
    data = s.recv(1024)
print(f'Received: {data!r}')