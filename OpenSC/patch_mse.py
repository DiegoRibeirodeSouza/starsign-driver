import re

with open("src/libopensc/card-starsign.c", "r") as f:
    content = f.read()

content = re.sub(r'data\[0\] = 0x80;.*?data\[5\] = 0x01;', 
r'''data[0] = 0x84;
        data[1] = 0x01;
        data[2] = env->key_ref[0];
        data[3] = 0x80;
        data[4] = 0x01;
        data[5] = 0x02;''', content, flags=re.DOTALL)

with open("src/libopensc/card-starsign.c", "w") as f:
    f.write(content)

