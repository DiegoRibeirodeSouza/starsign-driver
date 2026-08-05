from pyasn1.codec.der.decoder import decode
import sys

def hexify(data):
    if isinstance(data, bytes):
        return data.hex()
    return str(data)

with open("/tmp/cert.bin", "rb") as f:
    der = f.read()

# the file might contain multiple records (it's a file of CDF records)
offset = 0
while offset < len(der) and der[offset] != 0:
    try:
        obj, rest = decode(der[offset:])
        print(obj.prettyPrint())
        offset = len(der) - len(rest)
    except Exception as e:
        print("Error at offset", offset, ":", e)
        break
