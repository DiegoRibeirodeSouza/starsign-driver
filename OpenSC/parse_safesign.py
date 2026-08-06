import re
with open('../research/strace_safesign.txt', 'r') as f:
    lines = f.readlines()
for i, line in enumerate(lines):
    if "SCardTransmit" in line and "pbSendBuffer=" in line:
        # Extract the buffer
        m = re.search(r'pbSendBuffer="([^"]+)"', line)
        if m:
            buf = m.group(1).replace("\\x", " ").strip()
            print(f"L{i}: {buf}")
