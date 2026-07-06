import struct

with open("tests/fixtures/spss/stats.exe", "rb") as f:
    f.seek(0x11496)
    thunk = f.read(6)
    print(f"Thunk bytes: {thunk.hex()}")

    disp32 = struct.unpack("<i", thunk[2:6])[0]
    print(f"Displacement: {disp32:#x} ({disp32})")

    rip_after = 0x12096 + 6
    target = rip_after + disp32
    print(f"RIP after: {rip_after:#x}")
    print(f"Target RVA: {target:#x}")

    iat_offset = target - 0x16000
    iat_file_off = 0x14a00 + iat_offset
    f.seek(iat_file_off)
    iat_val = struct.unpack("<Q", f.read(8))[0]
    print(f"IAT slot value at file offset {iat_file_off:#x}: {iat_val:#018x}")
    print(f"IAT offset from start: {iat_offset:#x} (aligned: {iat_offset % 8 == 0})")

    slot_idx = iat_offset // 8
    print(f"IAT slot index: {slot_idx}")
