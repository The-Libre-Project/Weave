import struct

with open('tests/fixtures/spss/stats.exe', 'rb') as f:
    data = f.read()

text_off = 0x400
text_size = 0x144f8
text_data = data[text_off:text_off + text_size]

targets = [0x128e0, 0x12096]
for i in range(len(text_data) - 5):
    if text_data[i] == 0xe8:
        rel32 = struct.unpack('<i', text_data[i+1:i+5])[0]
        rva = 0x1000 + i
        target = rva + 5 + rel32
        if target in targets:
            print(f'  Call at RVA {rva:#x} -> RVA {target:#x}')
    elif text_data[i] == 0xff and (text_data[i+1] & 0xf0) == 0x10:
        # call reg
        modrm = text_data[i+1]
        reg = (modrm >> 3) & 7
        if reg == 0:
            print(f'  call rax at RVA {0x1000 + i:#x}')
