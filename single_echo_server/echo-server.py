# Bind HOST PORT
# LISTEN
# ACCEPT REQUEST


import socket
PORT = 65435
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(('localhost', PORT))
    s.listen()
    print(f"Server started to listen on:{PORT}") #
    conn, addr = s.accept()
    print(f'Connected by {addr}')
    print(f'\nConn: {conn}')
    while True:
        data = conn.recv(2048)
        if not data:
            break
        conn.sendall(data)