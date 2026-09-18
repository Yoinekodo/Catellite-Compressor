"""テンソル量子化の品質指標（CPU のみ・GPU 不要・決定論的・再現可能）.

README ロードマップ #1「INT4/INT8 量子化の品質指標」に対応。

LLM の perplexity / 精度劣化は GPU 評価基盤（vLLM・lm-eval 等）が
必要なため対象外（README 本文に明記）。本スイートは CPU のみで
再現可能な「復元テンソルの数値忠実度」を safetensors 往復で測定する:

  - SNR [dB]   : 原文エネルギー / 誤差エネルギー比（高いほど忠実）
  - 余弦類似度    : ベクトル方向の一致度（1.0 = 完全一致）
  - MAE / RMSE / 最大絶対誤差 / 有限性

検証する性質（qbits = 4/8/16 で単調性）:
  1. qbits の増加に伴い SNR[dB] と余弦類似度は単調非減少
  2. qbits の増加に伴い MAE / RMSE / 最大絶対誤差は単調非増加
  3. FP16(qbits=16) は F32 原文に対してほぼ完全一致
  （決定論的シード・合成テンソル・GPU 不要で再現可能）
"""
import json
import math
import os
import random
import shutil
import struct
import subprocess
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CC = os.path.join(REPO, "src", "CatelliteCompressor")


def _f16_to_f32(u):
    s = (u >> 15) & 1
    e = (u >> 10) & 0x1F
    m = u & 0x3FF
    if e == 0:
        v = math.ldexp(m, -24)
    elif e == 31:
        v = math.inf if m == 0 else math.nan
    else:
        v = math.ldexp(m + 1024, e - 25)
    return -v if s else v


def _f32_to_f16(v):
    v = max(-65504.0, min(65504.0, float(v)))
    bits = struct.unpack("<I", struct.pack("<f", float(v)))[0]
    s = (bits >> 16) & 0x8000
    e = ((bits + 0x0FFF) >> 23) & 0xFF
    m = bits & 0x7FFFFF
    if e == 0xFF:
        return s | 0x7C00
    if e == 0:
        return s
    hb = ((e >> 1) << 10) | (m >> 21)
    if m & 0x1000:
        hb += 1
    return (s | hb) & 0xFFFF


def _f32_to_bf16(v):
    bits = struct.unpack("<I", struct.pack("<f", float(v)))[0]
    return (bits + 0x7FFF + ((bits >> 16) & 1)) >> 16


def _bf16_to_f32(u):
    bits = u << 16
    return struct.unpack("<f", struct.pack("<I", bits))[0]


# ---- 最小 safetensors 読み書き（numpy 不使用） ----
def write_safetensors(path, tensors):
    """tensors: {name: {"dtype","shape","vals":[float]}} → safetensors 書込."""
    hdr = {}
    blob = b""
    for name, t in tensors.items():
        dt = t["dtype"]
        raw = b""
        if dt == "F32":
            raw = b"".join(struct.pack("<f", v) for v in t["vals"])
        elif dt == "F64":
            raw = b"".join(struct.pack("<d", v) for v in t["vals"])
        elif dt == "F16":
            raw = b"".join(struct.pack("<H", _f32_to_f16(v)) for v in t["vals"])
        elif dt == "BF16":
            raw = b"".join(struct.pack("<H", _f32_to_bf16(v)) for v in t["vals"])
        else:
            raise AssertionError("unsupported dtype on write: " + dt)
        start = len(blob)
        blob += raw
        hdr[name] = {"dtype": dt, "shape": list(t["shape"]),
                     "data_offsets": [start, len(blob)]}
    hb = json.dumps(hdr, separators=(",", ":")).encode("utf-8")
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(hb)))
        f.write(hb)
        f.write(blob)


def read_safetensors(path):
    """safetensors → {name: {"dtype","shape","vals":[float]}}."""
    with open(path, "rb") as f:
        raw = f.read()
    hlen = struct.unpack("<Q", raw[:8])[0]
    hdr = json.loads(raw[8:8 + hlen].decode("utf-8"))
    blob = raw[8 + hlen:]
    out = {}
    for name, meta in hdr.items():
        if name == "__metadata__":
            continue
        dt = meta["dtype"]
        a, b = meta["data_offsets"]
        chunk = blob[a:b]
        vals = []
        if dt == "F32":
            for i in range(0, len(chunk), 4):
                vals.append(struct.unpack("<f", chunk[i:i + 4])[0])
        elif dt == "F64":
            for i in range(0, len(chunk), 8):
                vals.append(struct.unpack("<d", chunk[i:i + 8])[0])
        elif dt == "F16":
            for i in range(0, len(chunk), 2):
                vals.append(_f16_to_f32(struct.unpack("<H", chunk[i:i + 2])[0]))
        elif dt == "BF16":
            for i in range(0, len(chunk), 2):
                vals.append(_bf16_to_f32(struct.unpack("<H", chunk[i:i + 2])[0]))
        else:
            raise AssertionError("unsupported dtype on read: " + dt)
        out[name] = {"dtype": dt, "shape": meta["shape"], "vals": vals}
    return out


def make_vals(seed, n, scale=2.0):
    """決定論的な合成テンソル値（量子化誤差が顕在化する分布）。"""
    r = random.Random(seed)
    vals = [math.sin(i * 0.17) * scale + math.cos(i * 0.031) * scale * 0.6
            for i in range(n)]
    for i in range(n):
        vals[i] += r.gauss(0, 0.3)
    for i in range(0, n, 997):
        vals[i] += scale  # 極大スパイク：相対量子化誤差を顕在化
    return vals


def metrics(orig, rest):
    """orig/rest: [float] → 数値忠実度指標."""
    n = min(len(orig), len(rest))
    if n == 0:
        return {"snr_db": math.nan, "cosine": math.nan, "mae": math.nan,
                "rmse": math.nan, "max_abs_err": math.nan}
    so = sum(x * x for x in orig)
    sr = sum(x * x for x in rest)
    dot = sum(o * r for o, r in zip(orig, rest))
    err2 = sum((o - r) ** 2 for o, r in zip(orig, rest))
    mae = sum(abs(o - r) for o, r in zip(orig, rest)) / n
    rmse = math.sqrt(err2 / n)
    maxe = max((abs(o - r) for o, r in zip(orig, rest)), default=0.0)
    cos = dot / math.sqrt(so * sr) if so > 0 and sr > 0 else 0.0
    snr = 10.0 * math.log10(so / err2) if err2 > 0 else math.inf
    return {"snr_db": snr, "cosine": cos, "mae": mae, "rmse": rmse,
            "max_abs_err": maxe}


class QualityBase(unittest.TestCase):
    CC = DEFAULT_CC
    KEEP = False

    @classmethod
    def setUpClass(cls):
        if not os.path.exists(cls.CC):
            raise unittest.SkipTest("binary not found: %s (build first)" % cls.CC)

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="catcmp_qual_")

    def tearDown(self):
        if not self.KEEP and self.tmp and os.path.isdir(self.tmp):
            shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cc(self, *args, timeout=600):
        return subprocess.run([self.CC] + list(args), capture_output=True,
                              text=True, timeout=timeout, cwd=self.tmp)

    def p(self, name):
        return os.path.join(self.tmp, name)

    def roundtrip(self, src, qbits, tag):
        arch = self.p(tag + ".catcmp")
        r = self.run_cc("c", "--qbits=%d" % qbits, src, arch)
        self.assertEqual(r.returncode, 0, "pack failed: " + r.stderr[-400:])
        out = self.p(tag + "_rest.safetensors")
        r = self.run_cc("d", arch, out)
        self.assertEqual(r.returncode, 0, "unpack failed: " + r.stderr[-400:])
        if not os.path.exists(out):
            import glob
            cands = sorted(c for c in glob.glob(os.path.join(self.tmp, tag + "_rest*"))
                           if os.path.isfile(c))
            self.assertTrue(cands, "no restored file for " + tag)
            out = cands[0]
        return out


class TestTensorQuality(QualityBase):
    def _make(self):
        return self.p("model.safetensors")

    def _write_model(self):
        write_safetensors(self._make(), {
            "attn.q.weight": {"dtype": "F32", "shape": [64, 64],
                              "vals": make_vals(11, 4096)},
            "mlp.up.weight": {"dtype": "F32", "shape": [32, 128],
                              "vals": make_vals(22, 4096, 4.0)},
            "emb.weight":    {"dtype": "F32", "shape": [2048, 2],
                              "vals": make_vals(33, 4096, 8.0)},
        })

    def test_fidelity_monotonic(self):
        """qbits 4→8→16 で SNR/余弦は単調非減少、誤差は単調非増加。"""
        src = self._make()
        self._write_model()
        orig = read_safetensors(src)
        byq = {q: {} for q in (16, 8, 4)}
        for q in (16, 8, 4):
            rest = read_safetensors(self.roundtrip(src, q, "m%d" % q))
            self.assertEqual(set(rest), set(orig), "tensor set mismatch q=%d" % q)
            for name in orig:
                byq[q][name] = metrics(orig[name]["vals"], rest[name]["vals"])

        for name in orig:
            snr = [byq[q][name]["snr_db"] for q in (16, 8, 4)]
            cos = [byq[q][name]["cosine"] for q in (16, 8, 4)]
            mae = [byq[q][name]["mae"] for q in (16, 8, 4)]
            rmse = [byq[q][name]["rmse"] for q in (16, 8, 4)]
            maxe = [byq[q][name]["max_abs_err"] for q in (16, 8, 4)]
            # SNR / 余弦: qbits 増加で単調非減少
            self.assertTrue(snr[0] >= snr[1] >= snr[2],
                            "SNR not monotonic for %s: %s" % (name, snr))
            self.assertTrue(cos[0] >= cos[1] >= cos[2],
                            "cosine not monotonic for %s: %s" % (name, cos))
            # 誤差: qbits 増加で単調非増加
            self.assertTrue(mae[0] <= mae[1] <= mae[2],
                            "MAE not monotonic for %s: %s" % (name, mae))
            self.assertTrue(rmse[0] <= rmse[1] <= rmse[2],
                            "RMSE not monotonic for %s: %s" % (name, rmse))
            self.assertTrue(maxe[0] <= maxe[1] <= maxe[2],
                            "max-abs-err not monotonic for %s: %s" % (name, maxe))
            # FP16 (qbits=16) はほぼ無損
            self.assertGreater(snr[0], 40.0,
                               "FP16 SNR too low for %s" % name)
            self.assertGreater(cos[0], 0.9999,
                               "FP16 cosine not near-1 for %s" % name)

    def test_binary_accepts_each_qbits(self):
        """qbits=16/8/4 は pack を成功させ、サイズは qbits に単調対応。"""
        src = self._make()
        self._write_model()
        sizes = {}
        for q in (16, 8, 4):
            arch = self.p("arch%d.catcmp" % q)
            r = self.run_cc("c", "--qbits=%d" % q, src, arch)
            self.assertEqual(r.returncode, 0,
                             "pack qbits=%d failed: %s" % (q, r.stderr[-400:]))
            sizes[q] = os.path.getsize(arch)
        # 精度が下がるほど小さくなる（INT4 < INT8 < FP16）
        self.assertLess(sizes[4], sizes[8])
        self.assertLess(sizes[8], sizes[16])

    def test_speed_rss_finite(self):
        """CPUのみ・決定論的・GPU不要: pack/unpack の実時間[s] と
        子プロセス最大RSS[kB] が有限非負であることを検証。

        time.monotonic + resource.RUSAGE_CHILDREN.ru_maxrss を使用
        （/usr/bin/time 不要、外部ベンチデータ不要、決定論的）。
        """
        import time
        import resource
        src = self._make()
        self._write_model()
        tag = "speed_rss"
        arch = self.p(tag + ".catcmp")
        t0 = time.monotonic()
        r = self.run_cc("c", "--qbits=16", src, arch)
        pack_s = time.monotonic() - t0
        pack_rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        self.assertEqual(r.returncode, 0,
                         "pack failed: " + r.stderr[-300:])
        out = self.p(tag + "_rest.safetensors")
        t0 = time.monotonic()
        r = self.run_cc("d", arch, out)
        unpack_s = time.monotonic() - t0
        unpack_rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        self.assertEqual(r.returncode, 0,
                         "unpack failed: " + r.stderr[-300:])
        # 有限かつ非負
        for v in (pack_s, unpack_s, pack_rss, unpack_rss):
            self.assertTrue(v == v and v >= 0, "non-finite or negative: %r" % v)
        # 可逆確認（既存 roundtrip と同等）
        self.assertTrue(os.path.exists(out))

        # Markdown 行出力（README#2 用）
        try:
            os.makedirs(os.path.join(REPO, "docs"), exist_ok=True)
            with open(os.path.join(REPO, "docs", "bench_memory.md"), "a") as f:
                f.write(
                    "| %s | %.3f | %.0f | %.3f | %.0f | %s |\n" %
                    ("1", pack_s, pack_rss, unpack_s, unpack_rss,
                     os.path.getsize(arch)))
        except OSError:
            pass


if __name__ == "__main__":
    import argparse
    import sys
    ap = argparse.ArgumentParser()
    ap.add_argument("--cc", default=DEFAULT_CC)
    ap.add_argument("--keep", action="store_true")
    args, rest = ap.parse_known_args()
    QualityBase.CC = args.cc
    QualityBase.KEEP = args.keep
    unittest.main(argv=[sys.argv[0]] + rest, verbosity=2)
