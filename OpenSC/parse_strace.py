import re

with open('../research/strace_safesign.txt', 'r') as f:
    for line in f:
        if "SCardTransmit" in line and "pbSendBuffer=" in line:
            m = re.search(r'pbSendBuffer="([^"]+)"', line)
            if m:
                raw = m.group(1)
                # Convert strace format to hex bytes
                res = []
                i = 0
                while i < len(raw):
                    if raw[i] == '\\':
                        if i+1 < len(raw) and raw[i+1] == 'x':
                            res.append(int(raw[i+2:i+4], 16))
                            i += 4
                        elif i+1 < len(raw) and raw[i+1] in '01234567':
                            oct_str = ""
                            i += 1
                            while i < len(raw) and raw[i] in '01234567' and len(oct_str) < 3:
                                oct_str += raw[i]
                                i += 1
                            res.append(int(oct_str, 8))
                        else:
                            char_map = {'n': 10, 'r': 13, 't': 9, '\\': 92, '"': 34}
                            res.append(char_map.get(raw[i+1], ord(raw[i+1])))
                            i += 2
                    else:
                        res.append(ord(raw[i]))
                        i += 1
                
                hx = " ".join(f"{x:02X}" for x in res)
                print(hx)
