import struct

with open("tests/fixtures/spss/stats.exe", "rb") as f:
    f.seek(0x3c)
    pe_off = struct.unpack("<I", f.read(4))[0]

    f.seek(pe_off)
    sig = f.read(4)

    coff_base = pe_off + 4
    f.seek(coff_base)
    machine = struct.unpack("<H", f.read(2))[0]
    num_sects = struct.unpack("<H", f.read(2))[0]
    f.read(4)  # timestamp
    f.read(4)  # symtab ptr
    f.read(4)  # numsym
    opt_hdr_size = struct.unpack("<H", f.read(2))[0]

    sect_off = coff_base + 20 + opt_hdr_size
    f.seek(sect_off)

    sections = []
    for i in range(num_sects):
        raw = f.read(8)
        name = raw.rstrip(b"\x00").decode("ascii", errors="replace")
        vsize = struct.unpack("<I", f.read(4))[0]
        vrva = struct.unpack("<I", f.read(4))[0]
        rsize = struct.unpack("<I", f.read(4))[0]
        roff = struct.unpack("<I", f.read(4))[0]
        sections.append((name, vrva, vsize, roff, rsize))
        f.read(16)

    def rva_to_offset(rva):
        for name, vrva, vsize, roff, rsize in sections:
            if vrva <= rva < vrva + vsize:
                return roff + (rva - vrva)
        return None

    opt_base = coff_base + 20
    f.seek(opt_base + 0)
    magic = struct.unpack("<H", f.read(2))[0]

    data_dir_off = opt_base + 112  # PE32+
    f.seek(data_dir_off + 1*8)
    import_rva = struct.unpack("<I", f.read(4))[0]

    off = rva_to_offset(import_rva)

    desc_idx = 0
    while True:
        ioff = off + desc_idx * 20
        f.seek(ioff)
        data = f.read(20)
        at_rva = struct.unpack("<I", data[0:4])[0]
        ts_rva = struct.unpack("<I", data[12:16])[0]
        ft_rva = struct.unpack("<I", data[16:20])[0]

        if at_rva == 0 and ts_rva == 0:
            break

        dll_name_off = rva_to_offset(ts_rva)
        f.seek(dll_name_off)
        dll_name = b""
        while True:
            c = f.read(1)
            if c == b"\x00":
                break
            dll_name += c
        dll_name = dll_name.decode()

        thunk_off = rva_to_offset(at_rva)
        thunk_count = 0
        while True:
            toff = thunk_off + thunk_count * 8
            f.seek(toff)
            t_val = struct.unpack("<Q", f.read(8))[0]
            if t_val == 0:
                break
            thunk_count += 1

        iat_start = ft_rva
        iat_end = ft_rva + thunk_count * 8

        print(f"Import[{desc_idx}]: {dll_name}")
        print(f"  Thunks: {at_rva:#x}, IAT: {ft_rva:#x} - {iat_end:#x} ({thunk_count} entries)")

        # Check each IAT slot
        for i in range(thunk_count):
            iat_rva = ft_rva + i * 8
            if 0x16d00 <= iat_rva <= 0x16d20:
                toff2 = thunk_off + i * 8
                f.seek(toff2)
                t_val2 = struct.unpack("<Q", f.read(8))[0]
                if t_val2 & 0x8000000000000000:
                    ordinal = t_val2 & 0xffff
                    print(f"  IAT[{i}] @ {iat_rva:#x}: mfc140u!ordinal #{ordinal}")
                else:
                    hint_name_off = rva_to_offset(t_val2 & 0xffffffff)
                    f.seek(hint_name_off)
                    hint = struct.unpack("<H", f.read(2))[0]
                    name = b""
                    while True:
                        c = f.read(1)
                        if c == b"\x00":
                            break
                        name += c
                    print(f"  IAT[{i}] @ {iat_rva:#x}: {name.decode()}")

        desc_idx += 1
