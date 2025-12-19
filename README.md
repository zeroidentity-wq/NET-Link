# Sockets

## TCP Sockets
![TCP](sockets-tcp.avif)

### Single-Echo-Server

#### Echo Server
```python
# SERVER
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
```

```pycon
# CLIENT
import socket
PORT = 65435
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # connectare
    s.connect(('localhost', PORT))
    s.sendall(b'Hello World')
    data = s.recv(1024)
print(f'Received: {data!r}')
```
---
> Diffs `.send()` & `.sendall()`  
> Apeleaza `.send()` & `.recv()` pana toate datele sunt trimise

#### Packet Sniffer
```python
import socket
import struct
import textwrap


# Funcție pentru a formata adresele MAC (ca să arate frumos: AA:BB:CC...)
def get_mac_addr(bytes_addr):
    # Transformă bytes în hex și îi unește cu ":"
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


# Funcție pentru a formata adresele IP
def get_ip_addr(bytes_addr):
    return '.'.join(map(str, bytes_addr))


def main():
    # 1. Creăm un socket RAW. Asta înseamnă că primim tot ce trece prin placa de rețea,
    # nu doar ce e pentru noi.
    # ntohs(0x0003) înseamnă că ascultăm toate protocoalele (ETH_P_ALL)
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    print("[*] Sniffer pornit... Aștept pachete...")

    while True:
        # 2. Primim datele brute (raw_data) și adresa de unde vin
        raw_data, addr = conn.recvfrom(65536)

        # --- LAYER 2: ETHERNET ---
        # Destinatar (6 bytes), Sursa (6 bytes), Protocol (2 bytes) = 14 bytes total
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        print('\n' + '-' * 60)
        print(f'Ethernet Frame:')
        print(f'\tDestination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')

        # --- LAYER 3: IPv4 ---
        # Dacă protocolul este 8 (adică IPv4), intrăm mai adânc
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print(f'\tIPv4 Packet:')
            print(f'\t\tVersion: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(f'\t\tProtocol: {proto}, Source: {src}, Target: {target}')

            # --- LAYER 4: Aici am putea adăuga TCP/UDP/ICMP ---


# Funcția care "desface" camionul (Ethernet Frame)
def ethernet_frame(data):
    # "6s" = 6 bytes (MAC), "H" = unsigned short (2 bytes - Protocolul)
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


# Funcția care "desface" coletul (IPv4 Header)
def ipv4_packet(data):
    version_header_length = data[0]
    # Bitwise operation pentru a extrage versiunea (primii 4 biți)
    version = version_header_length >> 4
    # Ultimii 4 biți * 4 bytes = lungimea headerului
    header_length = (version_header_length & 15) * 4

    # Despachetăm: TTL(8x), Protocol(1 byte), Sursa(4 bytes), Destinația(4 bytes)
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, get_ip_addr(src), get_ip_addr(target), data[header_length:]


if __name__ == '__main__':
    main()
```

