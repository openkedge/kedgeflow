"""Archive semantics only; synthetic ELF headers do not qualify runtime behavior."""

import hashlib
import io
import runpy
import struct
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
P = runpy.run_path(str(ROOT / "scripts/package-terraform-linux.py"))


class TerraformPackage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.bins = self.base / "bin"
        self.bins.mkdir()
        header = bytearray(64)
        header[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HHI", header, 16, 2, 183, 1)
        for n in P["BINS"]:
            (self.bins / n).write_bytes(header)
        self.result = P["package"](self.bins, self.base / "out")
        self.path = Path(self.result["archive"])

    def test_pinned_closed_bundle_is_deterministic(self):
        first = self.path.read_bytes()
        other = P["package"](self.bins, self.base / "other")
        self.assertEqual(first, Path(other["archive"]).read_bytes())
        self.assertFalse(P["verify"](self.path, self.result["sha256"])["production_qualified"])

    def test_wrong_digest_and_links_refuse(self):
        with self.assertRaises(ValueError):
            P["verify"](self.path, "0" * 64)
        link = self.base / "link"
        link.symlink_to(self.path)
        with self.assertRaises((ValueError, OSError)):
            P["verify"](link, self.result["sha256"])

    def test_unsafe_or_extra_members_refuse_even_with_matching_outer_digest(self):
        with tarfile.open(self.path, "r:gz") as original:
            items = [(m, original.extractfile(m).read()) for m in original]
        for mode in ["escape", "link", "extra", "privileged", "owner", "duplicate"]:
            with self.subTest(mode=mode):
                blob = io.BytesIO()
                with tarfile.open(fileobj=blob, mode="w:gz") as tf:
                    for m, b in items:
                        tf.addfile(m, io.BytesIO(b))
                    m = tarfile.TarInfo(
                        "../escape"
                        if mode == "escape"
                        else items[0][0].name
                        if mode == "duplicate"
                        else items[0][0].name.split("/")[0] + "/extra"
                    )
                    m.mode = 0o4755 if mode == "privileged" else 0o644
                    m.uid = 123 if mode == "owner" else 0
                    m.size = 1
                    if mode == "link":
                        m.type = tarfile.SYMTYPE
                        m.linkname = "/etc/passwd"
                        m.size = 0
                    tf.addfile(m, io.BytesIO(b"x"))
                path = self.base / (mode + ".tar.gz")
                data = blob.getvalue()
                path.write_bytes(data)
                with self.assertRaises((ValueError, KeyError)):
                    P["verify"](path, hashlib.sha256(data).hexdigest())


if __name__ == "__main__":
    unittest.main()
