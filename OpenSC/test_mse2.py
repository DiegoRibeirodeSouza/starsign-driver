from smartcard.System import readers
from smartcard.util import toHexString

def transmit(conn, apdu):
    print(f"> {toHexString(apdu)}")
    data, sw1, sw2 = conn.transmit(apdu)
    print(f"< {toHexString(data)} {sw1:02X} {sw2:02X}")
    return sw1, sw2

r = readers()[0]
conn = r.createConnection()
conn.connect()

print("Trying MSE SET with CLA=00...")
transmit(conn, [0x00, 0x22, 0x41, 0xB6, 0x06, 0x80, 0x01, 0x12, 0x84, 0x01, 0x01])

print("Trying MSE SET with CLA=00 (Alg=02)...")
transmit(conn, [0x00, 0x22, 0x41, 0xB6, 0x06, 0x80, 0x01, 0x02, 0x84, 0x01, 0x01])

