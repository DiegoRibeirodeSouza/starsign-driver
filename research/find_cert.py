import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'proto')))
from starsign_proto import connect, drm_handshake, open_logical_channel_1, init_pkcs15_channel1, tx, read_binary_full
from smartcard.System import readers

def main():
    rs = readers()
    if not rs:
        print("No readers")
        return
    conn = connect(rs[0])
    conn.disconnect()
    conn.connect()
    drm_handshake(conn)
    open_logical_channel_1(conn)
    init_pkcs15_channel1(conn)

    # Authenticate with PIN
    # The PIN from the user's log is "<SEU_PIN_AQUI>" padded with nulls
    pin_cmd = [0x01, 0x20, 0x00, 0x02, 0x0F] + list(b"<SEU_PIN_AQUI>" + b"\x00" * 6)
    data, sw1, sw2 = tx(conn, pin_cmd, "VERIFY PIN")
    if sw1 == 0x90:
        print("PIN verified successfully!")
    else:
        print(f"PIN failed: {sw1:02X}{sw2:02X}")

    print("Searching for large EFs in DF 5031...")
    
    # Common PKCS#15 EF prefixes are 43, 44, 45, 46, 50, 60, 70, 80
    prefixes = [0x43, 0x44, 0x45, 0x46, 0x50, 0x60, 0x70, 0x80]
    for p in prefixes:
        for suffix in range(0x00, 0xFF + 1):
            cmd = [0x01, 0xA4, 0x02, 0x00, 0x02, p, suffix, 0x00]
            data, sw1, sw2 = conn.transmit(cmd)
            if sw1 == 0x90:
                print(f"Found EF {p:02X}{suffix:02X}")
                # Use read_binary_full to read the whole thing
                file_data = read_binary_full(conn, size=None, cla=0x01)
                if len(file_data) > 500:
                    print(f"  => SUCCESS! EF {p:02X}{suffix:02X} is large ({len(file_data)} bytes)!")
                    with open(f"/tmp/file_{p:02X}{suffix:02X}.bin", "wb") as f:
                        f.write(file_data)


if __name__ == "__main__":
    main()
