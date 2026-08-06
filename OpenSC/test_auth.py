from smartcard.System import readers
from smartcard.util import toHexString
import sys

def tx(apdu):
    print(f"> {toHexString(apdu)}")
    data, sw1, sw2 = conn.transmit(apdu)
    print(f"< {toHexString(data)} {sw1:02X} {sw2:02X}")
    return sw1, sw2

r = readers()[0]
conn = r.createConnection()
conn.connect()

# Open channel
tx([0x00, 0x70, 0x00, 0x00, 0x01])
# Select PKCS15
tx([0x01, 0xA4, 0x04, 0x00, 0x0C, 0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35])

# Hash to sign (32 bytes)
hash_data = [0]*32

# Verify PIN (using the correct PIN: <SEU_PIN_AQUI> = 31 32 33 34 35 36 37 38 39)
pin = b"<SEU_PIN_AQUI>"
pin_hex = [c for c in pin]
print("Verifying PIN...")
tx([0x01, 0x20, 0x00, 0x02, len(pin_hex)] + pin_hex)

print("Trying INTERNAL AUTHENTICATE with P2=01...")
tx([0x01, 0x88, 0x00, 0x01, len(hash_data)] + hash_data + [0x00])

print("Trying INTERNAL AUTHENTICATE with P2=00...")
tx([0x01, 0x88, 0x00, 0x00, len(hash_data)] + hash_data + [0x00])

print("Trying PERFORM SECURITY OPERATION (2A)...")
tx([0x01, 0x2A, 0x9E, 0x9A, len(hash_data)] + hash_data + [0x00])

