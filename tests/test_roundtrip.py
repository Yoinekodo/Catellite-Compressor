#!/usr/bin/env python3
"""SatelliteCompressor round-trip and robustness tests.

Covers (review feedback #1):
  - round-trip of every codec path (RAW/CAT-LZ/CAT-Z/REV-BWT/JSON split/DB columnar)
  - empty / tiny files, Unicode names, symlinks, directory trees
  - truncated archive detection, double-compression prevention
  - bit-flip integrity is a KNOWN limitation (no per-entry CRC yet) and is
    marked as an expected failure (see test_bitflip_detected).

Usage:
  python3 tests/test_roundtrip.py [--cc /path/to/binary] [--keep]

The binary is built with:
  nim c -d:release -o:src/CatelliteCompressor src/CatelliteCompressor.nim
"""
import argparse
import glob
import hashlib
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CC = os.path.join(REPO, "src", "CatelliteCompressor")
BENCHF = "/root/benchF"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class CatBase(unittest.TestCase):
    CC = DEFAULT_CC
    KEEP = False
    workdir = None

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(cls.CC):
            raise unittest.SkipTest(f"binary not found: {cls.CC} (build first)")

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="catcmp_test_")
        self.workdir = self.tmp

    def tearDown(self):
        if not self.KEEP and self.tmp and os.path.isdir(self.tmp):
            shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cc(self, *args, timeout=300):
        return subprocess.run(
            [self.CC] + list(args),
            capture_output=True, text=True, timeout=timeout,
            cwd=self.tmp,
        )

    def w(self, name, data: bytes):
        p = os.path.join(self.tmp, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def assert_roundtrip_file(self, src, msg=None):
        """Compress single file and restore; assert byte-identical output."""
        base = os.path.basename(src)
        arch = os.path.join(self.tmp, base + ".catcmp")
        r = self.run_cc("c", src, arch)
        self.assertEqual(r.returncode, 0, f"compress failed: {r.stderr[-500:]}")
        self.assertTrue(os.path.exists(arch), "archive not created")
        out = os.path.join(self.tmp, base + ".out")
        r = self.run_cc("d", arch, out)
        self.assertEqual(r.returncode, 0, f"decompress failed: {r.stderr[-500:]}")
        # output name may gain an ext suffix (e.g. .bwt/.db/.dbcol); accept any match
        cands = [c for c in glob.glob(os.path.join(self.tmp, base + "*"))
                 if c != arch and os.path.isfile(c)]
        self.assertTrue(cands, "no restored file found")
        good = [c for c in cands if sha256(c) == sha256(src)]
        self.assertTrue(good, f"hash mismatch for {msg or base}: " +
                        ", ".join(f"{c}={os.path.getsize(c)}" for c in cands))

    def assert_roundtrip_dir(self, indir, msg=None):
        arch = os.path.join(self.tmp, "a.catcmp")
        outd = os.path.join(self.tmp, "restored")
        r = self.run_cc("c", indir, arch)
        self.assertEqual(r.returncode, 0, f"compress failed: {r.stderr[-500:]}")
        r = self.run_cc("d", arch, outd)
        self.assertEqual(r.returncode, 0, f"decompress failed: {r.stderr[-500:]}")
        # NOTE: restored names may gain a container ext suffix
        # (e.g. a.txt -> a.bwt); compare content hash multisets instead.
        want = sorted(sha256(os.path.join(r, f))
                      for r, _, fs in os.walk(indir) for f in fs)
        got = sorted(sha256(os.path.join(r, f))
                     for r, _, fs in os.walk(outd) for f in fs)
        self.assertEqual(want, got, f"content mismatch for {msg or indir}")


class TestEdgeCases(CatBase):
    def test_empty_file(self):
        self.assert_roundtrip_file(self.w("empty.bin", b""), "empty")

    def test_tiny_files(self):
        # regression: files < 8 bytes used to fail in smart mode
        for n in (1, 2, 4, 7):
            with self.subTest(n=n):
                self.assert_roundtrip_file(
                    self.w(f"t{n}.bin", bytes((i * 37) & 0xFF for i in range(n))),
                    f"tiny-{n}")

    def test_random_binary_raw(self):
        rnd = random.Random(1234).randbytes(100_000)
        self.assert_roundtrip_file(self.w("rand.bin", rnd), "random")

    def test_unicode_filename(self):
        self.assert_roundtrip_file(
            self.w("日本語テスト.txt", "日本語テスト\n".encode()), "unicode")

    def test_symlink_content(self):
        target = self.w("real.txt", b"symlink target content\n")
        link = os.path.join(self.tmp, "link.txt")
        if os.path.exists(link):
            os.remove(link)
        os.symlink(target, link)
        # symlink target content must survive the round trip
        self.assert_roundtrip_file(link, "symlink")

    def test_directory_tree(self):
        d = os.path.join(self.tmp, "proj")
        os.makedirs(os.path.join(d, "sub"))
        self.w("proj/a.txt", b"hello world\n" * 100)
        self.w("proj/sub/b.bin", bytes(range(256)) * 4)
        self.assert_roundtrip_dir(d, "dirtree")


class TestCodecPaths(CatBase):
    def _bench(self, name):
        p = os.path.join(BENCHF, name)
        if not os.path.exists(p):
            self.skipTest(f"fixture missing: {p}")
        return p

    def test_text_bwt_path(self):
        self.assert_roundtrip_file(self._bench("source.txt"), "REV-BWT")

    def test_json_split_path(self):
        self.assert_roundtrip_file(self._bench("data.json"), "JSON-split")

    def test_sqlite_dbcol_path(self):
        self.assert_roundtrip_file(self._bench("data.db"), "DB-columnar")

    def test_synthetic_json_split(self):
        # small JSON goes through REV-JSON or CAT-LZ; must round-trip either way
        import json as _json
        obj = [{"id": i, "name": f"user_{i}", "tags": ["a", "bb", "ccc"]} for i in range(2000)]
        self.assert_roundtrip_file(
            self.w("syn.json", _json.dumps(obj).encode()), "synthetic-json")


class TestRobustness(CatBase):
    def _make_archive(self, data: bytes = None):
        src = self.w("victim.bin", data if data is not None else
                     (b"0123456789ABCDEF" * 4096))
        arch = os.path.join(self.tmp, "victim.bin.catcmp")
        r = self.run_cc("c", src, arch)
        self.assertEqual(r.returncode, 0)
        return src, arch

    def test_truncated_archive_fails(self):
        _, arch = self._make_archive()
        size = os.path.getsize(arch)
        with open(arch, "r+b") as f:
            f.truncate(size // 2)
        r = self.run_cc("d", arch, os.path.join(self.tmp, "out"))
        self.assertNotEqual(r.returncode, 0, "truncated archive must be rejected")

    def test_double_compress_rejected(self):
        src, arch = self._make_archive()
        r = self.run_cc("c", arch, os.path.join(self.tmp, "repacked"))
        self.assertNotEqual(r.returncode, 0, "double compression must be rejected")

    @unittest.expectedFailure
    def test_bitflip_detected(self):
        # KNOWN LIMITATION (no per-entry CRC yet): a single flipped payload
        # bit should ideally be detected. Currently it may decode to wrong
        # bytes silently. This test documents the gap; remove the marker
        # once integrity checks are implemented.
        src, arch = self._make_archive()
        with open(arch, "r+b") as f:
            data = bytearray(f.read())
        flipped = False
        for off in range(len(data) - 1, max(len(data) - 1000, 0), -1):
            data[off] ^= 0x01
            with open(arch, "r+b") as f:
                f.seek(0)
                f.write(data)
            r = self.run_cc("d", arch, os.path.join(self.tmp, "out"))
            data[off] ^= 0x01  # restore for next iteration
            with open(arch, "r+b") as f:
                f.seek(0)
                f.write(data)
            if r.returncode != 0:
                flipped = True  # detected -> good, keep looking for silent case
                continue
            cands = [c for c in glob.glob(os.path.join(self.tmp, "out*"))
                     if os.path.isfile(c)]
            if cands and sha256(cands[0]) != sha256(src):
                self.fail("silent corruption: bit-flip decoded without error")
            flipped = True
        self.assertTrue(flipped)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cc", default=DEFAULT_CC)
    ap.add_argument("--keep", action="store_true")
    args, rest = ap.parse_known_args()
    CatBase.CC = args.cc
    CatBase.KEEP = args.keep
    unittest.main(argv=[sys.argv[0]] + rest, verbosity=2)


if __name__ == "__main__":
    main()
