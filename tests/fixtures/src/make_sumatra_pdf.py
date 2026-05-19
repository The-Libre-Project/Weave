#!/usr/bin/env python3
"""Generate a minimal single-page PDF for the E3-M4 SumatraPDF gate test."""
import os


def make_pdf(out_path: str) -> None:
    parts = []

    def add(s: str) -> int:
        off = sum(len(p) for p in parts)
        parts.append(s.encode())
        return off

    add("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

    obj1_off = sum(len(p) for p in parts)
    add("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

    obj2_off = sum(len(p) for p in parts)
    add("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")

    stream_content = b"BT /F1 36 Tf 72 720 Td (Hello Weave) Tj ET\n"
    obj3_off = sum(len(p) for p in parts)
    add(
        f"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]\n"
        f"   /Resources << /Font << /F1 4 0 R >> >>\n"
        f"   /Contents 5 0 R >>\nendobj\n"
    )

    obj4_off = sum(len(p) for p in parts)
    add("4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")

    obj5_off = sum(len(p) for p in parts)
    stream_len = len(stream_content)
    add(f"5 0 obj\n<< /Length {stream_len} >>\nstream\n")
    parts.append(stream_content)
    add("endstream\nendobj\n")

    xref_off = sum(len(p) for p in parts)
    offsets = [obj1_off, obj2_off, obj3_off, obj4_off, obj5_off]
    xref = "xref\n0 6\n"
    xref += "0000000000 65535 f \n"
    for o in offsets:
        xref += f"{o:010d} 00000 n \n"
    add(xref)
    add(f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref_off}\n%%EOF\n")

    data = b"".join(parts)
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "wb") as f:
        f.write(data)
    print(f"wrote {len(data)} bytes to {out_path}")


if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(script_dir, "..", "sumatrapdf", "test.pdf")
    make_pdf(out)
