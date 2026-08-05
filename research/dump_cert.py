import sys
from smartcard.System import readers

import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'proto')))
from starsign_proto import connect, drm_handshake, open_logical_channel_1, init_pkcs15_channel1, tx, read_binary_full

def main():
    rs = readers()
    if not rs:
        print("No readers")
        return
    r = rs[0]
    conn = connect(r)
    drm_handshake(conn)
    open_logical_channel_1(conn)
    init_pkcs15_channel1(conn)
    
    # Read EF 44 00
    data, sw1, sw2 = tx(conn, [0x01, 0xA4, 0x02, 0x00, 0x02, 0x44, 0x00, 0x00], "SELECT EF 44 00")
    if sw1 == 0x90:
        cert_data = read_binary_full(conn, size=None, cla=0x01)
        with open("/tmp/cert.bin", "wb") as f:
            f.write(cert_data)
        print(f"Saved {len(cert_data)} bytes to /tmp/cert.bin")
    else:
        print("Failed to select EF 44 00")

if __name__ == "__main__":
    main()
