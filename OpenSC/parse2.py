import re
with open('../research/strace_safesign.txt', 'r') as f:
    for line in f:
        if "SCardTransmit" in line and "pbSendBuffer" in line:
            if "3F" in line and "FF" in line:
                print(line.strip())
