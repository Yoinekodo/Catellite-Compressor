import std/[os, strutils, streams, algorithm, json, math, times, base64]

# ---- SHA-256 (pure Nim, no external deps) ----
proc sha256(data: openArray[byte]): array[32, byte] =
  const
    K = [
      0x428a2f98'u32, 0x71374491'u32, 0xb5c0fbcf'u32, 0xe9b5dba5'u32,
      0x3956c25b'u32, 0x59f111f1'u32, 0x923f82a4'u32, 0xab1c5ed5'u32,
      0xd807aa98'u32, 0x12835b01'u32, 0x243185be'u32, 0x550c7dc3'u32,
      0x72be5d74'u32, 0x80deb1fe'u32, 0x9bdc06a7'u32, 0xc19bf174'u32,
      0xe49b69c1'u32, 0xefbe4786'u32, 0x0fc19dc6'u32, 0x240ca1cc'u32,
      0x2de92c6f'u32, 0x4a7484aa'u32, 0x5cb0a9dc'u32, 0x76f988da'u32,
      0x983e5152'u32, 0xa831c66d'u32, 0xb00327c8'u32, 0xbf597fc7'u32,
      0xc6e00bf3'u32, 0xd5a79147'u32, 0x06ca6351'u32, 0x14292967'u32,
      0x27b70a85'u32, 0x2e1b2138'u32, 0x4d2c6dfc'u32, 0x53380d13'u32,
      0x650a7354'u32, 0x766a0abb'u32, 0x81c2c92e'u32, 0x92722c85'u32,
      0xa2bfe8a1'u32, 0xa81a664b'u32, 0xc24b8b70'u32, 0xc76c51a3'u32,
      0xd192e819'u32, 0xd6990624'u32, 0xf40e3585'u32, 0x106aa070'u32,
      0x19a4c116'u32, 0x1e376c08'u32, 0x2748774c'u32, 0x34b0bcb5'u32,
      0x391c0cb3'u32, 0x4ed8aa4a'u32, 0x5b9cca4f'u32, 0x682e6ff3'u32,
      0x748f82ee'u32, 0x78a5636f'u32, 0x84c87814'u32, 0x8cc70208'u32,
      0x90befffa'u32, 0xa4506ceb'u32, 0xbef9a3f7'u32, 0xc67178f2'u32
    ]
  var h = [
    0x6a09e667'u32, 0xbb67ae85'u32, 0x3c6ef372'u32, 0xa54ff53a'u32,
    0x510e527f'u32, 0x9b05688c'u32, 0x1f83d9ab'u32, 0x5be0cd19'u32
  ]
  var msg = newSeq[byte](data.len + 1 + 8)
  for i in 0..<data.len: msg[i] = data[i]
  msg[data.len] = 0x80'u8
  let bitLen = uint64(data.len) * 8
  for i in 0..<8: msg[msg.high - 7 + i] = byte((bitLen shr (8 * (7 - i))) and 0xFF)
  var w: array[64, uint32]
  for blockStart in countup(0, msg.high - 63, 64):
    for t in 0..15:
      let i = blockStart + t * 4
      w[t] = uint32(msg[i]) shl 24
      w[t] = w[t] or (uint32(msg[i+1]) shl 16)
      w[t] = w[t] or (uint32(msg[i+2]) shl 8)
      w[t] = w[t] or uint32(msg[i+3])
    for t in 16..63:
      let s0 = (w[t-15] shr 7 or w[t-15] shl 25) xor
               (w[t-15] shr 18 or w[t-15] shl 14) xor
               (w[t-15] shr 3)
      let s1 = (w[t-2] shr 17 or w[t-2] shl 15) xor
               (w[t-2] shr 19 or w[t-2] shl 13) xor
               (w[t-2] shr 10)
      w[t] = w[t-16] + s0 + w[t-7] + s1
    var a = h[0]; var b = h[1]; var c = h[2]; var d = h[3]
    var e = h[4]; var f = h[4]; var g = h[6]; var h1 = h[7]
    for t in 0..63:
      let S1 = (e shr 6 or e shl 26) xor (e shr 11 or e shl 21) xor (e shr 25 or e shl 7)
      let ch = (e and f) xor ((not e) and g)
      let temp1 = h1 + S1 + ch + K[t] + w[t]
      let S0 = (a shr 2 or a shl 30) xor (a shr 13 or a shl 19) xor (a shr 22 or a shl 10)
      let maj = (a and b) xor (a and c) xor (b and c)
      let temp2 = S0 + maj
      h1 = g; g = f; f = e; e = d + temp1
      d = c; c = b; b = a; a = temp1 + temp2
    h[0] += a; h[1] += b; h[2] += c; h[3] += d
    h[4] += e; h[5] += f; h[6] += g; h[7] += h1
  var hashOut: array[32, byte]
  for i in 0..7:
    for j in 0..3:
      hashOut[i*4 + j] = byte((h[i] shr (8*(3-j))) and 0xFF)
  return hashOut

proc sha256File(path: string): array[32, byte] =
  let sz = getFileSize(path).int
  var f: File
  if not f.open(path, fmRead):
    raise newException(IOError, "ファイルを開けません: " & path)
  var data = newSeq[byte](sz.Natural)
  discard f.readBytes(data, 0, sz.Natural)
  f.close()
  return sha256(data)

proc sha256Hex(h: array[32, byte]): string =
  var sb = ""
  for b in h: sb.add b.toHex(2).toLowerAscii
  return sb

const CatMagic = "CATCOMP1"
const FormatVersion = 2.uint8
const WindowSize = 65535
const LzWindow = 65535
const MinMatch = 4  # old LZ constant (CAT-Z overrides to 8)
const LazyThresh = 2
const MaxMatchLen = 255
const ChunkSize = 1 shl 20
const SampleSize = 1 shl 18
const RawThreshold = 0.97
const HashBits = 18
const HashSize = 1 shl HashBits
const HashBits2 = 15
const HashSize2 = 1 shl HashBits2
const HashBitsZ = 21
const HashSizeZ = 1 shl HashBitsZ
const HashBits2Z = 16
const HashSize2Z = 1 shl HashBits2Z

const KindEnd = 0.uint8
const KindSingle = 1.uint8
const KindMember = 2.uint8

const MethodRaw = 0.uint8
const MethodVm = 1.uint8
const MethodMp4 = 2.uint8
const MethodLossy = 3.uint8
const MethodCatLz = 4.uint8
const MethodJson = 5.uint8
const MethodCatZ = 6.uint8

# 一時ファイル置き場(小さな /tmp(tmpfs) を避け、実ディスク上を利用)
proc ccTmpDir(): string =
  result = getEnv("CATCOMP_TMP")
  if result == "": result = "/root/.catcc_tmp"
  try: createDir(result)
  except: result = "."

const OpLit = 1.uint8
const OpLitLong = 2.uint8
const OpRle = 3.uint8
const OpMatch = 4.uint8
const OpRepeat = 5.uint8

const Usage = "==================================\n" &
  " CatelliteCompressor v2 (.catcmp / CAT-VM + CAT-LZ + CAT-Z)\n" &
  "==================================\n" &
  "使い方:\n" &
  " 圧縮: ./CatelliteCompressor c [オプション] <入力(ファイル/Dir)> <出力>\n" &
  " 復元: ./CatelliteCompressor d [--base=<基準モデル>] <入力> <出力>\n" &
  "オプション:\n" &
  " (既定)         ハイブリッドモード: 拡張子に応じた最適圧縮を自動選択\n" &
  "                .safetensors/.pt/.bin → AIモデル圧縮(INT4量子化等)\n" &
  "                それ以外 → CAT-Z(LZMA2最適化圧縮)\n" &
  " --safe         完全可逆モード(全ファイル)\n" &
  " --safe=ai      AIモデルのみ可逆(通常ファイルは通常圧縮)\n" &
  " --lossy[=q]    スマートモードを明示(q=0高品質〜51最小, 既定51)\n" &
  " --base         モデル-aware圧縮(デルタ圧縮): 最初のsafetensorsを基準に\n" &
  " --qbits=[auto|16|8|4]\n" &
  "                テンソル量子化ビット(既定 auto=最小サイズ自動選択)\n" &
  "                4 = INT4(1/4, 最小) / 8 = INT8(1/2) / 16 = FP16(高品質)\n" &
  " 対応変換: 動画→mp4 / 画像→webp / 音声→opus (ffmpeg, 任意)\n" &
  "          safetensors→INT量子化(復元時は入力と同じ dtype へ逆量子化)\n" &
  "          3D(.obj)→頂点丸め\n" &
  " ※ 外部コマンド非依存(ffmpeg は任意)。7z/sqlite3 不要\n" &
  " ※ .catcmp 拡張子は省略可能 / ストリーミング処理(一時ファイル不要)"

proc wU16le(s: Stream, v: uint64) =
  s.write uint8(v and 0xFF)
  s.write uint8((v shr 8) and 0xFF)

proc wU32le(s: Stream, v: uint64) =
  s.write uint8(v and 0xFF)
  s.write uint8((v shr 8) and 0xFF)
  s.write uint8((v shr 16) and 0xFF)
  s.write uint8((v shr 24) and 0xFF)

proc wU64le(s: Stream, v: uint64) =
  wU32le(s, v and 0xFFFFFFFF.uint64)
  wU32le(s, v shr 32)

proc wU32be(s: Stream, v: uint64) =
  s.write uint8((v shr 24) and 0xFF)
  s.write uint8((v shr 16) and 0xFF)
  s.write uint8((v shr 8) and 0xFF)
  s.write uint8(v and 0xFF)

proc wU64be(s: Stream, v: uint64) =
  for k in countdown(56, 0):
    s.write uint8((v shr k) and 0xFF)

proc rU8(s: Stream): uint64 = uint64(s.readUint8())

proc rU16le(s: Stream): uint64 =
  rU8(s) or (rU8(s) shl 8)

proc rU32le(s: Stream): uint64 =
  rU8(s) or (rU8(s) shl 8) or (rU8(s) shl 16) or (rU8(s) shl 24)

proc rU64le(s: Stream): uint64 =
  rU32le(s) or (rU32le(s) shl 32)

proc fail(msg: string) =
  raise newException(IOError, msg)

# ---- CRC32C (Castagnoli, reflected) ----
const crc32cTable = block:
  var t: array[256, uint32]
  for i in 0..255:
    var c = uint32(i)
    for _ in 0..<8:
      c = if (c and 1) != 0: (c shr 1) xor 0x82F63B78'u32 else: c shr 1
    t[i] = c
  t

proc crc32cFile(path: string): uint32 =
  var f = openFileStream(path, fmRead)
  var ch = newString(1 shl 18)
  var crc = 0xFFFFFFFF'u32
  while not f.atEnd():
    let n = f.readData(addr ch[0], ch.len)
    if n <= 0: break
    for i in 0..<n:
      crc = crc32cTable[int((crc xor uint32(uint8(ch[i]))) and 0xFF)] xor (crc shr 8)
  f.close()
  crc xor 0xFFFFFFFF'u32

# エントリ末尾トレーラ: checksumType(u8) + checksum(u32LE)
#   type 0 = 検証なし(非可逆エントリ) / type 1 = CRC32C(原文 or 復元後ファイル)
proc entryCsumWrite(s: Stream, ctype: uint8, cval: uint32) =
  s.write ctype
  s.write uint8(cval and 0xFF)
  s.write uint8((cval shr 8) and 0xFF)
  s.write uint8((cval shr 16) and 0xFF)
  s.write uint8((cval shr 24) and 0xFF)

proc verifyEntryCsum(inp: Stream, ver: int, finalPath: string) =
  if ver < 2: return
  let ctype = uint8(inp.rU8())
  let cval = rU32le(inp)
  if ctype == 1:
    let got = crc32cFile(finalPath)
    if got != uint32(cval):
      try: removeFile(finalPath)
      except CatchableError: discard
      fail("復元データの整合性チェックに失敗しました(CRC32C不一致): " & finalPath & "\n" &
           "       アーカイブが破損しているか、元データと異なる内容が復元されています")

proc hashAt(buf: string, i: int): uint32 =
  let x = uint32(uint8(buf[i])) or
          (uint32(uint8(buf[i+1])) shl 8) or
          (uint32(uint8(buf[i+2])) shl 16) or
          (uint32(uint8(buf[i+3])) shl 24)
  (x * 2654435761.uint32) shr (32 - HashBits)

proc hashAt2(buf: string, i: int): uint32 =
  let x = uint32(uint8(buf[i])) or
          (uint32(uint8(buf[i+1])) shl 8) or
          (uint32(uint8(buf[i+2])) shl 16)
  (x * 2654435761.uint32) shr (32 - HashBits2)

# LZMA互換マッチファインダ用 (より大きなハッシュテーブル)
proc hashAtZ(buf: string, i: int): uint32 =
  let x = uint32(uint8(buf[i])) or
          (uint32(uint8(buf[i+1])) shl 8) or
          (uint32(uint8(buf[i+2])) shl 16) or
          (uint32(uint8(buf[i+3])) shl 24)
  (x * 2654435761.uint32) shr (32 - HashBitsZ)

proc hashAt2Z(buf: string, i: int): uint32 =
  let x = uint32(uint8(buf[i])) or
          (uint32(uint8(buf[i+1])) shl 8) or
          (uint32(uint8(buf[i+2])) shl 16)
  (x * 2654435761.uint32) shr (32 - HashBits2Z)

# ---- BWT 可逆変換(テキスト用) ----
proc bwtEncode(s: string): tuple[bwt: string, primary: int] =
  let n0 = s.len
  if n0 == 0: return ("", 0)
  var t = s & "\x00"
  let n = t.len
  var suf = newSeq[int](n)
  for i in 0..<n: suf[i] = i
  # radix sort by suffixes: sort by rank of each byte, doubling (O(n log n))
  var rank = newSeq[int](n)
  var tmp = newSeq[int](n)
  # initial rank by first byte
  for i in 0..<n: rank[i] = int(uint8(t[i]))
  var k = 1
  proc cmp(a, b: int): int =
    if rank[a] != rank[b]: return rank[a] - rank[b]
    let ra = if a+k < n: rank[a+k] else: -1
    let rb = if b+k < n: rank[b+k] else: -1
    return ra - rb
  while k < n:
    suf.sort(cmp)
    tmp[suf[0]] = 0
    var r = 0
    for i in 1..<n:
      let prev = suf[i-1]
      let cur = suf[i]
      let eq = cmp(prev, cur) == 0
      tmp[cur] = if eq: tmp[prev] else: r+1
      if not eq: inc r
    for i in 0..<n: rank[i] = tmp[i]
    if r == n-1: break
    k = k shl 1
  var prim = 0
  for i in 0..<n:
    if suf[i] == 0:
      prim = i; break
  var bwt = newString(n)
  for i in 0..<n:
    let idx = suf[i]
    bwt[i] = if idx == 0: '\x00' else: t[idx-1]
  result = (bwt, prim)

proc bwtDecode(bwt: string, primary: int): string =
  let n = bwt.len
  if n == 0: return ""
  if n == 1: return bwt
  var cnt = newSeq[int](256)
  for c in bwt: inc cnt[uint8(c)]
  var start = newSeq[int](256)
  var sum = 0
  for i in 0..<256:
    start[i] = sum
    sum += cnt[i]
  var occ = newSeq[int](256)
  var lf = newSeq[int](n)
  for i in 0..<n:
    let c = int(uint8(bwt[i]))
    lf[i] = start[c] + occ[c]
    inc occ[c]
  var tmp = newString(n)
  var idx = primary
  for i in countdown(n-1, 0):
    tmp[i] = bwt[idx]
    idx = lf[idx]
  # tmp は t (= s + "\x00"), 末尾の sentinel を除去して s を復元
  if tmp.len > 0 and tmp[^1] == '\x00':
    result = tmp[0..^2]
  else:
    result = tmp

# ---- SQLite 可逆変換用の共有ヘルパー ----
# SQLite varint (big-endian base-128) のデコード。範囲外参照時は ok=false。
proc sqliteVarint(b: string, o: int, lim: int): tuple[v: int, l: int, ok: bool] =
  var v = 0
  for i in 0..<9:
    if o + i >= lim: return (0, 0, false)
    let c = int(uint8(b[o+i]))
    if i == 8:
      v = (v shl 8) or c
      return (v, i+1, true)
    v = (v shl 7) or (c and 0x7F)
    if (c and 0x80) == 0: return (v, i+1, true)
  return (v, 9, true)

# SQLite シリアルタイプ -> 値バイト長。不正値は -1。
proc sqliteSerLen(st: int): int =
  if st == 0 or st == 8 or st == 9: return 0
  if st >= 1 and st <= 6: return st
  if st == 7: return 8
  if st >= 12 and (st mod 2) == 0: return (st-12) div 2
  if st >= 13: return (st-13) div 2
  return -1

proc vmEncode(src, dst: Stream, inputLimit: uint64): uint64 =
  var head: array[HashSize, int64]
  for i in 0..<HashSize: head[i] = -1
  var buf = ""
  var base = 0
  var idx = 0
  var eof = false
  var lit = ""
  var written: uint64 = 0
  var readTotal: uint64 = 0

  proc flushLit() =
    if lit.len == 0: return
    if lit.len >= 256:
      dst.write OpLitLong
      wU16le(dst, uint64(lit.len))
      written += uint64(3 + lit.len)
    else:
      dst.write OpLit
      dst.write uint8(lit.len)
      written += uint64(2 + lit.len)
    dst.write lit
    lit.setLen(0)

  proc refill() =
    if eof: return
    let want: int = int(min(uint64(ChunkSize), inputLimit - readTotal))
    if want == 0:
      eof = true
      return
    let oldLen = buf.len
    buf.setLen(oldLen + want)
    let got = src.readData(addr buf[oldLen], want)
    buf.setLen(oldLen + got)
    readTotal += uint64(got)
    if readTotal >= inputLimit or got < want:
      eof = true
    if buf.len > 8 * ChunkSize:
      let cut = idx - WindowSize
      if cut > 0:
        buf.delete(0 .. cut - 1)
        base += cut
        dec(idx, cut)

  refill()
  while true:
    if not eof: refill()
    let limit = if eof: buf.len else: buf.len - WindowSize
    if limit <= idx:
      if eof: break
      continue
    while idx < limit:
      let b0 = buf[idx]
      var run = 1
      while idx + run < limit and buf[idx + run] == b0:
        inc run
      if run >= 8:
        flushLit()
        dst.write OpRle
        dst.write b0
        wU32le(dst, uint64(run))
        written += 6
        inc(idx, run)
        continue
      block matchSearch:
        if idx + MinMatch <= limit:
          let h = hashAt(buf, idx)
          let cand = head[h]
          head[h] = int64(base + idx)
          if cand >= 0:
            let off = (base + idx) - cand
            if off >= 1 and off <= WindowSize and cand >= base:
              let maxLen = min(limit - idx, MaxMatchLen)
              var l = 0
              let cpos = cand - base
              while l < maxLen and buf[cpos + l] == buf[idx + l]:
                inc l
              if l >= MinMatch:
                var ext = l
                while ext < limit - idx and buf[idx + ext - off] == buf[idx + ext]:
                  inc ext
                flushLit()
                if ext >= 520 and ext >= off + 260:
                  dst.write OpRepeat
                  wU16le(dst, uint64(off))
                  wU32le(dst, uint64(ext))
                  written += 7
                else:
                  var rem = ext
                  while rem > 0:
                    let take = min(rem, MaxMatchLen)
                    dst.write OpMatch
                    wU16le(dst, uint64(off))
                    dst.write uint8(take)
                    written += 4
                    rem -= take
                let insEnd = min(ext, 4096)
                for k in 1..<insEnd:
                  if ext <= 4096 or k mod 4 == 0:
                    if idx + k + MinMatch <= limit:
                      head[hashAt(buf, idx + k)] = int64(base + idx + k)
                inc(idx, ext)
                break matchSearch
        lit.add b0
        if lit.len == 65535: flushLit()
        inc idx
    if eof and idx >= buf.len: break
  flushLit()
  result = written

proc vmDecode(src, dst: Stream, origSize: uint64) =
  var outBuf = ""
  var hist = ""
  var produced: uint64 = 0

  proc emit(c: char) =
    if produced >= origSize: fail("アーカイブが破損しています(サイズ超過)")
    outBuf.add c
    hist.add c
    if hist.len >= 2 * LzWindow + ChunkSize:
      hist.delete(0 .. LzWindow - 1)
    inc produced
    if outBuf.len >= ChunkSize:
      dst.write outBuf
      outBuf.setLen(0)

  if origSize == 0: return
  while produced < origSize:
    if src.atEnd(): fail("アーカイブが破損しています(データ不足)")
    let op = src.readUint8()
    case op
    of OpLit:
      let n = int(src.readUint8())
      var t = newString(n)
      if n > 0 and src.readData(addr t[0], n) != n:
        fail("アーカイブが破搊しています")
      for ch in t: emit(ch)
    of OpLitLong:
      let n = int(rU16le(src))
      var t = newString(n)
      if n > 0 and src.readData(addr t[0], n) != n:
        fail("アーカイブが破損しています")
      for ch in t: emit(ch)
    of OpRle:
      let b = char(src.readUint8())
      let n = rU32le(src)
      for _ in 1..n: emit(b)
    of OpMatch:
      let off = int(rU16le(src))
      let ln = int(src.readUint8())
      if off < 1 or off > hist.len: fail("アーカイブが破損しています(MATCH)")
      for _ in 1..ln:
        emit(hist[hist.len - off])
    of OpRepeat:
      let off = int(rU16le(src))
      let total = rU32le(src)
      if off < 1 or off > hist.len: fail("アーカイブが破損しています(REPEAT)")
      for _ in 1..total:
        emit(hist[hist.len - off])
    else:
      fail("アーカイブが破損しています(不明な命令)")
  if outBuf.len > 0:
    dst.write outBuf

proc copyExact(src, dst: Stream, n: uint64) =
  var tmp = newString(ChunkSize)
  var left = n
  while left > 0:
    let want = int(min(left, uint64(tmp.len)))
    let got = src.readData(addr tmp[0], want)
    if got <= 0: fail("アーカイブが破損しています(RAW)")
    dst.writeData(addr tmp[0], got)
    left -= uint64(got)

# ---- CAT-LZ: 内製 高密度可逆 LZ コーデック(外部ツール不要) ----
# 8項目ごとにフラグバイトを置き、リテラル 9bit / マッチ 17bit〜 に圧縮する。
# ウィンドウは 64KB(u16 オフセット)。長さは 1 バイト(3..257)、
# 超過時は 255 エスケープ + u32。復号は元バイト列と完全一致します。
proc lzEncode(src, dst: Stream, inputLimit: uint64): uint64 =
  # v2: 4MB ウィンドウ / u32 オフセットエスケープ / lazy matching
  var head: array[HashSize, int64]
  for i in 0..<HashSize: head[i] = -1
  var buf = ""
  var base = 0
  var idx = 0
  var eof = false
  var written: uint64 = 0
  var readTotal: uint64 = 0
  var flags: uint8 = 0
  var nflags = 0
  var pend = ""

  var dbgLit = 0
  var dbgMth = 0
  var dbgMlen = 0
  proc flushGroup() =
    if nflags == 0: return
    dst.write uint8(flags)
    dst.write pend
    written += uint64(1 + pend.len)
    flags = 0
    nflags = 0
    pend.setLen(0)

  proc addItem(isMatch: bool, payload: string) =
    if isMatch:
      flags = flags or uint8(1.uint8 shl nflags)
    pend.add payload
    inc nflags
    if nflags == 8: flushGroup()

  proc emitMatch(off: int64, l: int) =
    inc dbgMth; dbgMlen += l
    var tok = ""
    if off <= 65535:
      tok.add char(uint8(off and 0xFF))
      tok.add char(uint8((off shr 8) and 0xFF))
    else:
      tok.add char(0'u8)
      tok.add char(0'u8)
      let uo = uint32(off)
      tok.add char(uint8(uo and 0xFF))
      tok.add char(uint8((uo shr 8) and 0xFF))
      tok.add char(uint8((uo shr 16) and 0xFF))
      tok.add char(uint8((uo shr 24) and 0xFF))
    let lb = l - 3
    if lb <= 254:
      tok.add char(uint8(lb))
    else:
      tok.add char(255.uint8)
      let ul = uint32(l)
      tok.add char(uint8(ul and 0xFF))
      tok.add char(uint8((ul shr 8) and 0xFF))
      tok.add char(uint8((ul shr 16) and 0xFF))
      tok.add char(uint8((ul shr 24) and 0xFF))
    addItem(true, tok)

  proc refill() =
    if eof: return
    let want: int = int(min(uint64(ChunkSize), inputLimit - readTotal))
    if want == 0:
      eof = true
      return
    let oldLen = buf.len
    buf.setLen(oldLen + want)
    let got = src.readData(addr buf[oldLen], want)
    buf.setLen(oldLen + got)
    readTotal += uint64(got)
    if readTotal >= inputLimit or got < want:
      eof = true
    if buf.len > LzWindow + 8 * ChunkSize:
      let cut = idx - LzWindow
      if cut > 0:
        buf.delete(0 .. cut - 1)
        base += cut
        dec(idx, cut)

  refill()
  while true:
    if not eof: refill()
    let margin = if eof: 0 else: LzWindow
    let limit = buf.len - margin
    if limit <= idx:
      if eof: break
      continue
    while idx < limit:
      var handled = false
      block tryMatch:
        if idx + MinMatch <= limit:
          let h = hashAt(buf, idx)
          let cand = head[h]
          head[h] = int64(base + idx)
          if cand >= base and cand >= 0:
            let off = (base + idx) - cand
            if off >= 1 and off <= LzWindow:
              let cpos = cand - base
              let maxLen = min(limit - idx, 0xFFFFFF)
              var l = 0
              while l < maxLen and buf[cpos + l] == buf[idx + l]:
                inc l
              if l >= MinMatch:
                # コスト判定: リテラル並みより得なら採用(遠距離は表記が重い)
                let litBits = 9.0 * float(l)
                var tokBits = 1.0 + (if off <= 65535: 16.0 else: 40.0)
                let lbv = l - 3
                tokBits += (if lbv <= 254: 8.0 else: 40.0)
                if tokBits < litBits and (off <= 65535 or l >= 32):
                  emitMatch(off, l)
                  let insEnd = min(l, 4096)
                  for k in 1..<insEnd:
                    if k mod 4 == 0:
                      if idx + k + MinMatch <= limit:
                        head[hashAt(buf, idx + k)] = int64(base + idx + k)
                  inc(idx, l)
                  handled = true
                  break tryMatch
                # 不採用(コスト劣) → リテラルへ落ちる
      if not handled:
        addItem(false, $buf[idx])
        inc dbgLit
        inc idx
    if eof and idx >= buf.len: break
  flushGroup()
  when defined CATCC_LZDBG:
    stderr.writeLine("lzdbg lit=",dbgLit," mth=",dbgMth," mlen=",dbgMlen,
                     " cov=",dbgLit+dbgMlen," idx=",idx," buflen=",buf.len," eof=",eof)
  result = written

proc lzDecode(src, dst: Stream, origSize: uint64) =
  var outBuf = ""
  var hist = ""
  var produced: uint64 = 0

  proc emit(c: char) =
    if produced >= origSize: fail("アーカイブが破損しています(LZ サイズ超過)")
    outBuf.add c
    hist.add c
    if hist.len >= 2 * LzWindow + ChunkSize:
      hist.delete(0 .. LzWindow - 1)
    inc produced
    if outBuf.len >= ChunkSize:
      dst.write outBuf
      outBuf.setLen(0)

  if origSize == 0: return
  while produced < origSize:
    if src.atEnd(): fail("アーカイブが破損しています(LZ データ不足)")
    let flags = src.readUint8()
    var bit = 0
    while bit < 8 and produced < origSize:
      if (flags and (1.uint8 shl bit)) == 0:
        if src.atEnd(): fail("アーカイブが破損しています(LZ リテラル)")
        emit(char(src.readUint8()))
      else:
        var off = int(rU16le(src))
        if off == 0:
          off = int(rU32le(src))
        let lb = int(src.readUint8())
        var ln: int
        if lb < 255:
          ln = lb + 3
        else:
          ln = int(rU32le(src))
        if off < 1 or off > hist.len: fail("アーカイブが破損しています(LZ MATCH)")
        if ln < 1: fail("アーカイブが破損しています(LZ LEN)")
        for _ in 1..ln:
          emit(hist[hist.len - off])
      inc bit
  if outBuf.len > 0:
    dst.write outBuf

# ---- CAT-Z: LZ + 適応範囲符号化(LZMA 方式) ----
# リテラルは直前バイト上位4bit 文脈の8分木、一致長は8bit木、
# オフセットはスロット木+反転ビット列で高精度に符号化する。
# 復元はバイト完全一致。
# LZMA2 (xz) 互換パラメータ:
#   lc=3, lp=0, pb=2 (デフォルト)
#   最大一致長=273, 辞書=64MB
const ProbBits = 15
const ZPosBits = 2              # LZMA2-style position bits (4 position contexts, like xz)
const ZPosStates = 1 shl ZPosBits  # 4
const ZSlots = 16
const ZLitCtx = 128
type Prob = uint16

# LZMA2 互換パラメータ
const Z_LC = 3                    # Literal context bits (8 contexts from top 3 bits of prev byte)
const Z_LP = 0                    # Literal position bits (0 = no position context)
const Z_PB = 2                    # Position bits (4 position states, like xz)
const Z_LC_MASK = (1 shl Z_LC) - 1  # 0x7 for lc=3

const MinMatchZ = 4                        # CAT-Z最小一致長
const ZMaxNb = 26                          # 最大オフセットビット(64MB辞書に必要)
const ZKeepBytes = 4 * 1024 * 1024
const ZMaxOff = 64 * 1024 * 1024           # 64MB dictionary (xz -9デフォルト)
const MaxChain = 2048                      # bt4 最大探索深さ (大幅拡大)
const NiceLen = 273                        # LZMA互換: これ以上のマッチは即採用
const FastBytes = 64                       # LZMA互換: この長さ以上なら探索打ち切り
const LazyMatchMin = 16                    # 遅延マッチ最小長

const OptBlock = 65536                     # 最適解析ブロックサイズ (xz互換: 64KB)
const MaxMatchZ = 273                      # xz互換: 最大一致長 273

var zNbBase: array[ZMaxNb + 2, int]
var zNbBaseInit = false

proc zInitOffBase() =
  if zNbBaseInit: return
  zNbBase[0] = 0
  zNbBase[1] = 0                  # nb=1 は追加ビット無し(ov=1)
  for n in 2..ZMaxNb + 1:
    zNbBase[n] = zNbBase[n-1] + (1 shl (n - 2))
  zNbBaseInit = true

var dbgTagId = 0
var dbgTagBytes: array[8, int64]

type RcEnc = object
  low: uint64
  rng: uint32
  cache: uint8
  cacheSize: int64
  pmove: int
  pbits: int
  dst: Stream

proc rcInitE(s: Stream, pm: int = 4, pb: int = 15): RcEnc =
  RcEnc(low: 0, rng: 0xFFFFFFFF.uint32, cache: 0, cacheSize: 1, pmove: pm, pbits: pb, dst: s)

proc rcShiftLow(e: var RcEnc) =
  if e.low < 0xFF000000.uint64 or (e.low shr 32) != 0.uint64:
    var temp = e.cache
    while true:
      e.dst.write uint8(temp + uint8(e.low shr 32))
      inc dbgTagBytes[dbgTagId]
      temp = 0xFF.uint8
      dec e.cacheSize
      if e.cacheSize <= 0: break
    e.cache = uint8((e.low shr 24) and 0xFF.uint64)
  inc e.cacheSize
  e.low = (e.low and 0x00FFFFFF.uint64) shl 8

var dbgEC = 0
proc rcEncBit(e: var RcEnc, p: var Prob, bit: int) =
  when defined CATCC_LZDBG:
    if dbgEC < 6000:
      stderr.writeLine("E", dbgEC, " p=", p, " bit=", bit)
    inc dbgEC
  let bound = uint32((uint64(e.rng shr e.pbits) * uint64(p)) shr 0)
  if bit == 0:
    e.rng = bound
  else:
    e.low += uint64(bound)
    e.rng -= bound
  while e.rng < (1.uint32 shl 24):
    rcShiftLow(e)
    e.rng = e.rng shl 8
  let top = 1 shl e.pbits
  var np = int(p)
  if bit == 0:
    np += (top - np) div (1 shl e.pmove)
  else:
    np -= np div (1 shl e.pmove)
  let loP = top shr 10
  if np < loP: np = loP
  elif np > top - loP: np = top - loP
  p = Prob(np)

proc rcFlush(e: var RcEnc) =
  for _ in 0..<5: rcShiftLow(e)

type RcDec = object
  rng: uint32
  code: uint32
  pmove: int
  pbits: int
  src: Stream

proc rcInitD(s: Stream, pm: int = 4, pb: int = 15): RcDec =
  var d = RcDec(rng: 0xFFFFFFFF.uint32, code: 0.uint32, pmove: pm, pbits: pb, src: s)
  for _ in 0..<5:
    d.code = (d.code shl 8) or uint32(d.src.readUint8())
  d

var dbgDC = 0
proc rcDecBit(d: var RcDec, p: var Prob): int =
  when defined CATCC_LZDBG:
    if dbgDC < 6000:
      stderr.writeLine("D", dbgDC, " p=", p)
    inc dbgDC
  let bound = uint32((uint64(d.rng shr d.pbits) * uint64(p)) shr 0)
  var bit = 1
  if d.code < bound:
    d.rng = bound
    bit = 0
  else:
    d.code -= bound
    d.rng -= bound
  while d.rng < (1.uint32 shl 24):
    d.rng = d.rng shl 8
    d.code = (d.code shl 8) or uint32(d.src.readUint8())
  let top = 1 shl d.pbits
  var np = int(p)
  if bit == 0:
    np += (top - np) div (1 shl d.pmove)
  else:
    np -= np div (1 shl d.pmove)
  let loP = top shr 10
  if np < loP: np = loP
  elif np > top - loP: np = top - loP
  p = Prob(np)
  result = bit

proc rcTreeEnc(e: var RcEnc, probs: var openArray[Prob], base: int, bits: int, sym: int) =
  var m = 1
  for k in countdown(bits - 1, 0):
    let bit = (sym shr k) and 1
    e.rcEncBit(probs[base + m], bit)
    m = (m shl 1) + bit

proc rcTreeDec(d: var RcDec, probs: var openArray[Prob], base: int, bits: int): int =
  var m = 1
  for _ in 0..<bits:
    let bit = rcDecBit(d, probs[base + m])
    m = (m shl 1) + bit
  result = m - (1 shl bits)

proc catZEncodeCore(src, dst: Stream, inputLimit: uint64, pmove: int, pbits: int, obSize: int, usePriced: bool, useGreedy: bool = false, maxChainOverride: int = -1, useLzmaLitCtx: bool = true): uint64 =
  let MaxChainEff = if maxChainOverride >= 0: maxChainOverride else: MaxChain
  var head = newSeq[int](HashSizeZ)
  for i in 0..<HashSizeZ: head[i] = -1
  var head2 = newSeq[int](HashSize2Z)
  for i in 0..<HashSize2Z: head2[i] = -1
  var chain = newSeq[int](ChunkSize * 2)
  for i in 0..<chain.len: chain[i] = -1
  var btLeft = newSeq[int](ChunkSize * 2)
  var btRight = newSeq[int](ChunkSize * 2)
  for i in 0..<btLeft.len:
    btLeft[i] = -1
    btRight[i] = -1
  var buf = ""
  var base = 0
  var idx = 0
  var eof = false
  var readTotal: uint64 = 0
  let startOff = dst.getPosition()
  var e = rcInitE(dst, pmove, pbits)
  let pInit = Prob(1 shl (pbits - 1))
  # 12-state LZMA2-style flag machine with position-dependent contexts
  var flagP: array[ZPosStates * 12, Prob]
  for i in 0..<flagP.len: flagP[i] = pInit
  # LZMA2互換: lc=3, lp=0, pb=2
  # リテラル文脈数 = (1<<lc) * (1<<lp) * ZPosStates = 8 * 1 * 4 = 32
  const LitStates = (1 shl Z_LC) * (1 shl Z_LP) * ZPosStates  # 32
  var litU: array[LitStates * 256, Prob]  # 32 * 256 = 8192 probs (root of bit trees)
  for i in 0..<litU.len: litU[i] = pInit
  # Match literal: matched byte from rep0 as context
  const MatchLitStates = 256  # matched byte value
  var litM: array[MatchLitStates * 512, Prob]
  for i in 0..<litM.len: litM[i] = pInit
  # lenP: 4 positions × 8 contexts × 256 (prevLenCls + wasRep selects context)
  var lenP: array[ZPosStates * 8 * 256, Prob]
  for i in 0..<lenP.len: lenP[i] = pInit
  # slotP: 8 contexts × 33 (prevOffsetNbCls selects context)
  var slotP: array[8 * 33, Prob]
  for i in 0..<slotP.len: slotP[i] = pInit
  let obMaxBits = ZMaxNb
  var obP = newSeq[Prob](1 shl obMaxBits)
  for i in 0..<obP.len: obP[i] = pInit
  var repP: array[2, Prob]
  for i in 0..<repP.len: repP[i] = pInit
  # selP: 4 positions × 8 contexts (position + which selects context)
  var selP: array[ZPosStates * 8, Prob]
  for i in 0..<selP.len: selP[i] = pInit
  var reps: array[4, int] = [0, 0, 0, 0]
  var prevLit = 0
  var state = 0  # LZMA2 12-state machine
  var prevMatchLen = 0  # for len context
  var prevOffsetNb = 0  # for offset slot context
  var prevPrevLit = 0  # two-literal-back context
  var dbgLitZ = 0
  var dbgMthZ = 0

  proc encFlag(isMatch: bool, pos: int) =
    if isMatch: inc dbgMthZ
    else: inc dbgLitZ
    e.rcEncBit(flagP[pos * 12 + state], isMatch.int)

  var lenEP: array[65536, Prob]
  for i in 0..<lenEP.len: lenEP[i] = pInit

  var dbgMlenZ = 0

  proc emitMatch(off: int64, l: int, pos: int) =
    dbgMlenZ += l
    let tagSave = dbgTagId
    # rep offset 判定
    var which = 4
    if off == reps[0]: which = 0
    elif off == reps[1]: which = 1
    elif off == reps[2]: which = 2
    elif off == reps[3]: which = 3
    when defined CATCC_LZDBG:
      let ovD = off - 1
      var sD = 0
      var tD = ovD
      while tD > 0:
        tD = tD shr 1
        inc sD
      inc dbgNb[sD]
      if which < 2: inc dbgRepCnt
    dbgTagId = 1
    e.rcTreeEnc(selP, pos * 8, 3, which)
    dbgTagId = 2
    # len context: prevLenCls(4) × wasRep(2) = 8 contexts × 4 positions
    var lv = l - 3
    let prevLenCls = if prevMatchLen <= 10: 0
                     elif prevMatchLen <= 40: 1
                     elif prevMatchLen <= 160: 2
                     else: 3
    let lenCtx = prevLenCls * 2 + (if which < 4: 1 else: 0)
    let lenBase = (pos * 8 + lenCtx) * 256
    if lv <= 253:
      e.rcTreeEnc(lenP, lenBase, 8, lv)
    else:
      e.rcTreeEnc(lenP, lenBase, 8, 255)
      dbgTagId = 3
      e.rcTreeEnc(lenEP, 0, 16, lv - 254)
    dbgTagId = 4
    if which == 4:
      let ov = off - 1
      var nb = 0
      var t = ov
      while t > 0:
        t = t shr 1
        inc nb
      let slotCtx = min(7, prevOffsetNb) * 33
      e.rcTreeEnc(slotP, slotCtx, 5, nb)
      dbgTagId = 5
      if nb > 1:
        let ev = ov - (1 shl (nb - 1))
        let bs = zNbBase[nb]
        var m = 0
        for k in countdown(nb - 2, 0):
          let bit = (ev shr k) and 1
          e.rcEncBit(obP[bs + m], bit)
          m = (m shl 1) + bit
      prevOffsetNb = nb
    # rep ローテーション (使用した offset を rep0 に昇格)
    if which != 0 and which <= 3:
      let tmp = reps[which]
      for i in countdown(which, 1):
        reps[i] = reps[i-1]
      reps[0] = tmp
    elif which == 4:
      reps[3] = reps[2]; reps[2] = reps[1]; reps[1] = reps[0]; reps[0] = off
    prevMatchLen = l
    dbgTagId = tagSave

  proc refill() =
    if eof: return
    let want: int = int(min(uint64(ChunkSize), inputLimit - readTotal))
    if want == 0:
      eof = true
      return
    let oldLen = buf.len
    buf.setLen(oldLen + want)
    let got = src.readData(addr buf[oldLen], want)
    buf.setLen(oldLen + got)
    if btLeft.len < buf.len:
      let oldLen = btLeft.len
      btLeft.setLen(buf.len)
      btRight.setLen(buf.len)
      chain.setLen(buf.len)
      for i in oldLen..<btLeft.len:
        btLeft[i] = -1
        btRight[i] = -1
        chain[i] = -1
    readTotal += uint64(got)
    if readTotal >= inputLimit or got < want:
      eof = true
    if buf.len > ZKeepBytes + 8 * ChunkSize:
      let cut = idx - ZKeepBytes
      if cut > 0:
        buf.delete(0 .. cut - 1)
        base += cut
        dec(idx, cut)
        btLeft = btLeft[cut .. ^1]
        btRight = btRight[cut .. ^1]
        chain = chain[cut .. ^1]

  refill()
  if useGreedy:
    let topP = 1 shl pbits
    var ct0g = newSeq[int32](topP)
    var ct1g = newSeq[int32](topP)
    for i in 0..<topP:
      let f = float64(i) / float64(topP)
      var v0 = (-log2(f)) * 64.0
      var v1 = (-log2(1.0 - f)) * 64.0
      if v0 < 1.0: v0 = 1.0
      if v1 < 1.0: v1 = 1.0
      ct0g[i] = int32(v0)
      ct1g[i] = int32(v1)

    proc gCost(p: Prob, bit: int): int64 =
      result = int64(if bit == 0: ct0g[p] else: ct1g[p])

    proc gTreeCost[T](probs: T, base, numBits, sym: int): int64 =
      result = 0
      var m = 1
      for k in countdown(numBits - 1, 0):
        let sb = (sym shr k) and 1
        result += gCost(probs[base + m], sb)
        m = (m shl 1) + sb

    while true:
      if not eof: refill()
      let margin = if eof: 0 else: ZMaxOff
      let limit = buf.len - margin
      if limit <= idx:
        if eof: break
        continue
      let gi = idx
      let pos = gi and (ZPosStates - 1)

      if gi + MinMatchZ > limit:
        encFlag(false, pos)
        let litCtx = if useLzmaLitCtx:
          (prevLit shr (8 - Z_LC)) * ZPosStates + pos
        else:
          min(state, 7) * 256 + prevLit
        let mctx = prevLit
        let symE = int(uint8(buf[gi]))
        if reps[0] > 0 and gi >= reps[0]:
          let mbv = int(uint8(buf[gi - reps[0]]))
          var m2 = 1
          var mb = mbv
          for k in countdown(7, 0):
            let mbit = (mb shr k) and 1
            let sbit = (symE shr k) and 1
            e.rcEncBit(litM[mctx * 512 + (m2 shl 1) + mbit], sbit)
            m2 = (m2 shl 1) + sbit
        else:
          e.rcTreeEnc(litU, litCtx * 256, 8, symE)
        state = if state < 7: 0 else: state - 6
        prevPrevLit = prevLit
        prevLit = symE
        prevMatchLen = 0
        inc idx
        continue

      # --- LZMA-style match finding with nice/fast bytes ---
      let h = hashAtZ(buf, gi)
      let h2 = hashAt2Z(buf, gi)
      let curAbs = base + gi
      var cp = head[h]
      head[h] = curAbs

      if cp >= 0:
        let cpRel = cp - base
        if cpRel >= 0 and cpRel < buf.len:
          var cmpOff = 0
          let maxCmp = min(min(limit - gi, 65541), min(buf.len - gi, buf.len - cpRel))
          while cmpOff < maxCmp and buf[gi + cmpOff] == buf[cpRel + cmpOff]:
            inc cmpOff
          if cmpOff >= maxCmp:
            btLeft[gi] = cp
          elif uint8(buf[gi + cmpOff]) < uint8(buf[cpRel + cmpOff]):
            btRight[gi] = cp
          else:
            btLeft[gi] = cp

      # Secondary hash chain (3-byte) for additional candidates
      var cp2 = head2[h2]
      head2[h2] = curAbs
      chain[gi] = cp2

      var bestL = 0
      var bestOff = 0
      var secL = 0
      var secOff = 0

      proc updateBest(l, off: int) =
        if l > bestL:
          secL = bestL; secOff = bestOff
          bestL = l; bestOff = off
        elif l > secL and l < bestL:
          secL = l; secOff = off

      # Primary: bt4 tree traversal with fast bytes / nice length optimization
      var treeDepth = 0
      var cpCur = cp
      while cpCur >= 0 and treeDepth < MaxChainEff:
        let off = curAbs - cpCur
        if off < 1 or off > ZMaxOff: break
        let cpRel = cpCur - base
        if cpRel < 0 or cpRel >= buf.len: break
        let maxLen = min(limit - gi, buf.len - cpRel)
        var l = 0
        while l < maxLen and buf[cpRel + l] == buf[gi + l]:
          inc l
        updateBest(l, off)
        # Nice length: accept immediately if match is long enough
        if l >= NiceLen: break
        # Fast bytes: if match is good enough, stop searching
        if l >= FastBytes and treeDepth > 10: break
        if l >= maxLen: break
        if cpRel + l < buf.len and gi + l < buf.len:
          if uint8(buf[gi + l]) < uint8(buf[cpRel + l]):
            cpCur = btLeft[cpRel]
          else:
            cpCur = btRight[cpRel]
        else:
          break
        inc treeDepth
        if bestL >= 256: break

      # Secondary: hash chain traversal (for additional candidates)
      var chainDepth = 0
      var cpS = chain[gi]
      while cpS >= 0 and chainDepth < 128:
        let off = curAbs - cpS
        if off < 1 or off > ZMaxOff: break
        let cpRel = cpS - base
        if cpRel < 0 or cpRel >= buf.len: break
        let maxLen = min(limit - gi, buf.len - cpRel)
        var l = 0
        while l < maxLen and buf[cpRel + l] == buf[gi + l]:
          inc l
        updateBest(l, off)
        if l >= NiceLen: break
        if l >= FastBytes: break
        let nextRel = cpS - base
        if nextRel < 0 or nextRel >= chain.len: break
        cpS = chain[nextRel]
        inc chainDepth
        if bestL >= 256: break

      # Check rep matches (recent offsets)
      for r in 0..<4:
        let off = reps[r]
        if off > 0 and gi >= off:
          let maxLen = min(limit - gi, 65541)
          var l = 0
          while l < maxLen and buf[gi - off + l] == buf[gi + l]:
            inc l
          if l >= MinMatchZ:
            updateBest(l, off)

      var litCost = gCost(flagP[pos * 12 + state], 0)
      block:
        let symE = int(uint8(buf[gi]))
        if reps[0] > 0 and gi >= reps[0]:
          let mbv = int(uint8(buf[gi - reps[0]]))
          let mctx = prevLit
          var m2 = 1
          var mb = mbv
          for k in countdown(7, 0):
            let mbit = (mb shr k) and 1
            let sbit = (symE shr k) and 1
            litCost += gCost(litM[mctx * 512 + (m2 shl 1) + mbit], sbit)
            m2 = (m2 shl 1) + sbit
        else:
          let litCtx = if useLzmaLitCtx:
            (prevLit shr (8 - Z_LC)) * ZPosStates + pos
          else:
            min(state, 7) * 256 + prevLit
          var m = 1
          for k in countdown(7, 0):
            let sbit = (symE shr k) and 1
            litCost += gCost(litU[litCtx * 256 + m], sbit)
            m = (m shl 1) + sbit

      var bestCost = litCost
      var useMatch = false
      var matchL = 0
      var matchOff = 0

      template priceMatch(ml, mo: int) =
        if ml >= MinMatchZ:
          var mc = gCost(flagP[pos * 12 + state], 1)
          var which = 4
          if mo == reps[0]: which = 0
          elif mo == reps[1]: which = 1
          elif mo == reps[2]: which = 2
          elif mo == reps[3]: which = 3
          mc += gTreeCost(selP, pos * 8, 3, which)
          let lv = ml - 3
          let prevLenCls = if prevMatchLen <= 10: 0
                           elif prevMatchLen <= 40: 1
                           elif prevMatchLen <= 160: 2
                           else: 3
          let lenCtx = prevLenCls * 2 + (if which < 4: 1 else: 0)
          let lenBase = (pos * 8 + lenCtx) * 256
          if lv <= 253:
            mc += gTreeCost(lenP, lenBase, 8, lv)
          else:
            mc += gTreeCost(lenP, lenBase, 8, 255)
            mc += gTreeCost(lenEP, 0, 16, lv - 254)
          if which == 4:
            let ov = mo - 1
            var nb = 0
            var t = ov
            while t > 0: t = t shr 1; inc nb
            nb = min(nb, ZMaxNb)
            let slotCtx = min(7, prevOffsetNb) * 33
            mc += gTreeCost(slotP, slotCtx, 5, nb)
            if nb > 1:
              let ev = ov - (1 shl (nb - 1))
              let bs = zNbBase[nb]
              var m3 = 0
              for k in countdown(nb - 2, 0):
                let sb = (ev shr k) and 1
                mc += gCost(obP[bs + m3], sb)
                m3 = (m3 shl 1) + sb
          if mc < bestCost:
            bestCost = mc
            useMatch = true
            matchL = ml
            matchOff = mo

      priceMatch(bestL, bestOff)
      if bestL < secL:
        priceMatch(secL, secOff)

      if useMatch:
        var which = 4
        if matchOff == reps[0]: which = 0
        elif matchOff == reps[1]: which = 1
        elif matchOff == reps[2]: which = 2
        elif matchOff == reps[3]: which = 3
        encFlag(true, pos)
        emitMatch(matchOff, matchL, pos)
        if which < 4:
          state = min(state + 1, 11)
        else:
          state = min(state + 3, 11)
        prevPrevLit = prevLit
        prevLit = int(uint8(buf[gi + matchL - 1]))
        prevMatchLen = matchL
        inc idx, matchL
      else:
        encFlag(false, pos)
        let litCtx = if useLzmaLitCtx:
          (prevLit shr (8 - Z_LC)) * ZPosStates + pos
        else:
          min(state, 7) * 256 + prevLit
        let mctx = prevLit
        let symE = int(uint8(buf[gi]))
        if reps[0] > 0 and gi >= reps[0]:
          let mbv = int(uint8(buf[gi - reps[0]]))
          var m2 = 1
          var mb = mbv
          for k in countdown(7, 0):
            let mbit = (mb shr k) and 1
            let sbit = (symE shr k) and 1
            e.rcEncBit(litM[mctx * 512 + (m2 shl 1) + mbit], sbit)
            m2 = (m2 shl 1) + sbit
        else:
          e.rcTreeEnc(litU, litCtx * 256, 8, symE)
        state = if state < 7: 0 else: state - 6
        prevPrevLit = prevLit
        prevLit = symE
        prevMatchLen = 0
        inc idx
    e.rcFlush()
    return uint64(dst.getPosition() - startOff)

  # Block-level DP path (flat or priced)
  # Block-level DP path (flat or priced)
  while true:
    if not eof: refill()
    let margin = if eof: 0 else: ZMaxOff
    let limit = buf.len - margin
    if limit <= idx:
      if eof: break
      continue
    # --- Optimal parser: process one block ---
    let blockEnd = min(limit, idx + obSize)
    let blockLen = blockEnd - idx
    if blockLen < MinMatchZ:
      if blockLen <= 0:
        if eof: break
        continue
      encFlag(false, idx and (ZPosStates - 1))
      # LZMA2互換リテラル文脈: lc=3, lp=0, pb=2 (useLzmaLitCtx=true)
      # 旧形式: state*256 + prevLit (より詳細な文脈)
      let pos = idx and (ZPosStates - 1)
      let litCtx = if useLzmaLitCtx:
        (prevLit shr (8 - Z_LC)) * ZPosStates + pos
      else:
        min(state, 7) * 256 + prevLit
      let mctx = prevLit
      let symE = int(uint8(buf[idx]))
      if reps[0] > 0 and idx >= reps[0]:
        let mbv = int(uint8(buf[idx - reps[0]]))
        var m2 = 1
        var mb = mbv
        for k in countdown(7, 0):
          let mbit = (mb shr k) and 1
          let sbit = (symE shr k) and 1
          e.rcEncBit(litM[mctx * 512 + (m2 shl 1) + mbit], sbit)
          m2 = (m2 shl 1) + sbit
      else:
        e.rcTreeEnc(litU, litCtx * 256, 8, symE)
      state = if state < 7: 0 else: state - 6
      prevPrevLit = prevLit
      prevLit = symE
      prevMatchLen = 0
      inc idx
    else:
      # Phase 1: Scan forward, build bt4 tree, collect matches per position
      var candL = newSeq[array[4, int]](blockLen)
      var candO = newSeq[array[4, int]](blockLen)
      for bi in 0..<blockLen:
        let gi = idx + bi
        candL[bi][0] = 0
        candO[bi][0] = 0
        candL[bi][1] = 0
        candO[bi][1] = 0
        candL[bi][2] = 0
        candO[bi][2] = 0
        candL[bi][3] = 0
        candO[bi][3] = 0
        if gi + MinMatchZ <= limit:
          let h = hashAtZ(buf, gi)
          let h2 = hashAt2Z(buf, gi)
          let curAbs = base + gi
          var cp = head[h]
          head[h] = curAbs
          if cp >= 0:
            let cpRel = cp - base
            if cpRel >= 0 and cpRel < buf.len:
              var cmpOff = 0
              let maxCmp = min(min(limit - gi, 65541), min(buf.len - gi, buf.len - cpRel))
              while cmpOff < maxCmp and buf[gi + cmpOff] == buf[cpRel + cmpOff]:
                inc cmpOff
              if cmpOff >= maxCmp:
                btLeft[gi] = cp
              elif uint8(buf[gi + cmpOff]) < uint8(buf[cpRel + cmpOff]):
                btRight[gi] = cp
              else:
                btLeft[gi] = cp
          var cp2 = head2[h2]
          head2[h2] = curAbs
          chain[gi] = cp2
          var bestL = 0
          var bestOff = 0
          var secL = 0
          var secOff = 0
          var thirdL = 0
          var thirdOff = 0
          var fourthL = 0
          var fourthOff = 0
          proc updTop4(l, off: int) =
            if l > bestL:
              fourthL = thirdL; fourthOff = thirdOff
              thirdL = secL; thirdOff = secOff
              secL = bestL; secOff = bestOff
              bestL = l; bestOff = off
            elif l > secL and l < bestL:
              fourthL = thirdL; fourthOff = thirdOff
              thirdL = secL; thirdOff = secOff
              secL = l; secOff = off
            elif l > thirdL and l < secL:
              fourthL = thirdL; fourthOff = thirdOff
              thirdL = l; thirdOff = off
            elif l > fourthL and l < thirdL:
              fourthL = l; fourthOff = off
          var treeDepth = 0
          var cpCur = cp
          while cpCur >= 0 and treeDepth < MaxChain:
            let off = curAbs - cpCur
            if off < 1 or off > ZMaxOff: break
            let cpRel = cpCur - base
            if cpRel < 0 or cpRel >= buf.len: break
            let maxLen = min(limit - gi, buf.len - cpRel)
            var l = 0
            while l < maxLen and buf[cpRel + l] == buf[gi + l]:
              inc l
            updTop4(l, off)
            # Nice length optimization
            if l >= NiceLen: break
            # Fast bytes optimization
            if l >= FastBytes and treeDepth > 10: break
            if l >= maxLen: break
            if cpRel + l < buf.len and gi + l < buf.len:
              if uint8(buf[gi + l]) < uint8(buf[cpRel + l]):
                cpCur = btLeft[cpRel]
              else:
                cpCur = btRight[cpRel]
            else:
              break
            inc treeDepth
            if bestL >= 256: break
          var chainDepth = 0
          var cpS = chain[gi]
          while cpS >= 0 and chainDepth < 256:
            let off = curAbs - cpS
            if off < 1 or off > ZMaxOff: break
            let cpRel = cpS - base
            if cpRel < 0 or cpRel >= buf.len: break
            let maxLen = min(limit - gi, buf.len - cpRel)
            var l = 0
            while l < maxLen and buf[cpRel + l] == buf[gi + l]:
              inc l
            updTop4(l, off)
            if l >= NiceLen: break
            if l >= FastBytes: break
            let nextRel = cpS - base
            if nextRel < 0 or nextRel >= chain.len: break
            cpS = chain[nextRel]
            inc chainDepth
            if bestL >= 256: break

          candL[bi][0] = bestL
          candO[bi][0] = bestOff
          candL[bi][1] = secL
          candO[bi][1] = secOff
          candL[bi][2] = thirdL
          candO[bi][2] = thirdOff
          candL[bi][3] = fourthL
          candO[bi][3] = fourthOff

      # Phase 2: parser DP — two modes: exact priced or flat-cost
      var dp = newSeq[int64](blockLen + 1)
      var dpChoice = newSeq[int](blockLen)
      var dpChoiceOff = newSeq[int](blockLen)
      if not usePriced:
        dp[blockLen] = 0
        for bi in countdown(blockLen - 1, 0):
          dp[bi] = dp[bi + 1] + 512
          dpChoice[bi] = 0
          dpChoiceOff[bi] = 0
          for ci in 0..<4:
            var cl = candL[bi][ci]
            if ci > 0 and cl >= candL[bi][0]: continue
            if cl > blockLen - bi: cl = blockLen - bi
            if cl < MinMatchZ: continue
            let nextBi = min(bi + cl, blockLen)
            let cost = dp[nextBi] + 1088
            if cost < dp[bi]:
              dp[bi] = cost
              dpChoice[bi] = cl
              dpChoiceOff[bi] = candO[bi][ci]
      else:
        # Priced mode: costs from actual probability tables (fixed point, 1/64 bit)
        let topP = 1 shl pbits
        var ct0 = newSeq[int32](topP)
        var ct1 = newSeq[int32](topP)
        for i in 0..<topP:
          let f = float64(i) / float64(topP)
          var v0 = (-log2(f)) * 64.0
          var v1 = (-log2(1.0 - f)) * 64.0
          if v0 < 1.0: v0 = 1.0
          if v1 < 1.0: v1 = 1.0
          ct0[i] = int32(v0)
          ct1[i] = int32(v1)
        var repsAt = newSeq[array[4, int32]](blockLen + 1)
        var stAt = newSeq[int32](blockLen + 1)
        var lcAt = newSeq[int32](blockLen + 1)   # prevMatchLen class
        var onAt = newSeq[int32](blockLen + 1)   # prevOffsetNb
        var plAt = newSeq[int32](blockLen + 1)   # prevLit

        for it in 0..<3:
          # Forward-simulate current choices to snapshot exact state at each position
          block:
            var sR: array[4, int]
            for i in 0..<4: sR[i] = reps[i]
            var sSt = state
            var sPl = prevLit
            var sLen = prevMatchLen
            var sNb = prevOffsetNb
            for bi2 in 0..<blockLen:
              for i in 0..<4: repsAt[bi2][i] = int32(sR[i])
              stAt[bi2] = int32(sSt)
              plAt[bi2] = int32(sPl)
              lcAt[bi2] = int32(if sLen <= 10: 0 elif sLen <= 40: 1 elif sLen <= 160: 2 else: 3)
              onAt[bi2] = int32(sNb)
              if dpChoice[bi2] > 0:
                let mo = dpChoiceOff[bi2]
                let ml = dpChoice[bi2]
                var w = 4
                if mo == sR[0]: w = 0
                elif mo == sR[1]: w = 1
                elif mo == sR[2]: w = 2
                elif mo == sR[3]: w = 3
                if w != 0 and w <= 3:
                  let tmpS = sR[w]
                  for i in countdown(w, 1): sR[i] = sR[i-1]
                  sR[0] = tmpS
                elif w == 4:
                  sR[3] = sR[2]; sR[2] = sR[1]; sR[1] = sR[0]; sR[0] = mo
                  var tN = mo - 1
                  var nbc = 0
                  while tN > 0: tN = tN shr 1; inc nbc
                  sNb = nbc
                sSt = min(sSt + (if w < 4: 1 else: 3), 11)
                sLen = ml
                sPl = int(uint8(buf[idx + bi2 + ml - 1]))
              else:
                sSt = if sSt < 7: 0 else: sSt - 6
                sLen = 0
                sPl = int(uint8(buf[idx + bi2]))
          # Backward DP using exact per-position state and real bit prices
          dp[blockLen] = 0
          for bi in countdown(blockLen - 1, 0):
            let gi = idx + bi
            let posC = gi and (ZPosStates - 1)
            let sym = int(uint8(buf[gi]))
            let r0 = repsAt[bi][0].int
            # literal cost (flag=0 + literal path)
            var litC = ct0[flagP[posC * 12 + stAt[bi]].int]
            if r0 > 0 and gi >= r0:
              let mbv = int(uint8(buf[gi - r0]))
              let mctx = plAt[bi].int
              var m2 = 1
              for k in countdown(7, 0):
                let mb = (mbv shr k) and 1
                let sb = (sym shr k) and 1
                let pr = litM[mctx * 512 + (m2 shl 1) + mb].int
                litC += (if sb == 0: ct0[pr] else: ct1[pr])
                m2 = (m2 shl 1) + sb
            else:
              # LZMA2互換リテラル文脈: lc=3, lp=0, pb=2 (useLzmaLitCtx=true)
              # 旧形式: state*256 + prevLit (より詳細な文脈)
              let litCtx = if useLzmaLitCtx:
                (plAt[bi].int shr (8 - Z_LC)) * ZPosStates + (gi and (ZPosStates - 1))
              else:
                min(stAt[bi], 7) * 256 + plAt[bi].int
              var m2 = 1
              for k in countdown(7, 0):
                let sb = (sym shr k) and 1
                let pr = litU[litCtx * 256 + m2].int
                litC += (if sb == 0: ct0[pr] else: ct1[pr])
                m2 = (m2 shl 1) + sb
            dp[bi] = dp[bi + 1] + litC.int64
            dpChoice[bi] = 0
            dpChoiceOff[bi] = 0
            # match candidates: up to 4 from bt4 BFS
            for ci in 0..<4:
              var cl = candL[bi][ci]
              if ci > 0 and cl >= candL[bi][0]: continue
              if cl > blockLen - bi: cl = blockLen - bi
              if cl < MinMatchZ: continue
              let co = candO[bi][ci]
              let nextBi = min(bi + cl, blockLen)
              var w = 4
              if co == r0: w = 0
              elif co == repsAt[bi][1].int: w = 1
              elif co == repsAt[bi][2].int: w = 2
              elif co == repsAt[bi][3].int: w = 3
              var mc = ct1[flagP[posC * 12 + stAt[bi]].int].int64
              block: # sel tree (3 bits)
                var m2 = 1
                for k in countdown(2, 0):
                  let sb = (w shr k) and 1
                  let pr = selP[posC * 8 + m2].int
                  mc += (if sb == 0: ct0[pr] else: ct1[pr]).int64
                  m2 = (m2 shl 1) + sb
              block: # len tree (8 bits, + escape)
                let lv = cl - 3
                let lenCtx = lcAt[bi].int * 2 + (if w < 4: 1 else: 0)
                let lbase = (posC * 8 + lenCtx) * 256
                let symL = min(lv, 255)
                var m2 = 1
                for k in countdown(7, 0):
                  let sb = (symL shr k) and 1
                  let pr = lenP[lbase + m2].int
                  mc += (if sb == 0: ct0[pr] else: ct1[pr]).int64
                  m2 = (m2 shl 1) + sb
                if lv > 253:
                  let ev = lv - 254
                  var m3 = 1
                  for k in countdown(15, 0):
                    let sb = (ev shr k) and 1
                    let pr = lenEP[m3].int
                    mc += (if sb == 0: ct0[pr] else: ct1[pr]).int64
                    m3 = (m3 shl 1) + sb
              if w == 4: # offset slot + extra bits
                block:
                  let ov = co - 1
                  var nbc = 0
                  var tO = ov
                  while tO > 0: tO = tO shr 1; inc nbc
                  nbc = min(nbc, ZMaxNb)
                  var m2 = 1
                  for k in countdown(4, 0):
                    let sb = (nbc shr k) and 1
                    let pr = slotP[min(7, onAt[bi].int) * 33 + m2].int
                    mc += (if sb == 0: ct0[pr] else: ct1[pr]).int64
                    m2 = (m2 shl 1) + sb
                  if nbc > 1:
                    let ev = ov - (1 shl (nbc - 1))
                    let bs = zNbBase[nbc]
                    var m3 = 0
                    for k in countdown(nbc - 2, 0):
                      let sb = (ev shr k) and 1
                      let pr = obP[bs + m3].int
                      mc += (if sb == 0: ct0[pr] else: ct1[pr]).int64
                      m3 = (m3 shl 1) + sb
              let cost = dp[nextBi] + mc
              if cost < dp[bi]:
                dp[bi] = cost
                dpChoice[bi] = cl
                dpChoiceOff[bi] = co

      # Phase 3: Encode according to DP decisions
      var bi = 0
      while bi < blockLen:
        let gi = idx + bi
        if dpChoice[bi] > 0:
          let ml = dpChoice[bi]
          let mo = dpChoiceOff[bi]
          var which = 4
          if mo == reps[0]: which = 0
          elif mo == reps[1]: which = 1
          elif mo == reps[2]: which = 2
          elif mo == reps[3]: which = 3
          encFlag(true, gi and (ZPosStates - 1))
          emitMatch(mo, ml, gi and (ZPosStates - 1))
          if which < 4:
            state = min(state + 1, 11)
          else:
            state = min(state + 3, 11)
          prevPrevLit = prevLit
          prevLit = int(uint8(buf[gi + ml - 1]))
          prevMatchLen = ml
          inc bi, ml
        else:
          encFlag(false, gi and (ZPosStates - 1))
          # LZMA2互換リテラル文脈: lc=3, lp=0, pb=2 (useLzmaLitCtx=true)
          # 旧形式: state*256 + prevLit (より詳細な文脈)
          let pos = gi and (ZPosStates - 1)
          let litCtx = if useLzmaLitCtx:
            (prevLit shr (8 - Z_LC)) * ZPosStates + pos
          else:
            min(state, 7) * 256 + prevLit
          let mctx = prevLit
          let symE = int(uint8(buf[gi]))
          if reps[0] > 0 and gi >= reps[0]:
            let mbv = int(uint8(buf[gi - reps[0]]))
            var m2 = 1
            var mb = mbv
            for k in countdown(7, 0):
              let mbit = (mb shr k) and 1
              let sbit = (symE shr k) and 1
              e.rcEncBit(litM[mctx * 512 + (m2 shl 1) + mbit], sbit)
              m2 = (m2 shl 1) + sbit
          else:
            e.rcTreeEnc(litU, litCtx * 256, 8, symE)
          state = if state < 7: 0 else: state - 6
          prevPrevLit = prevLit
          prevLit = symE
          prevMatchLen = 0
          inc bi
      idx += bi
    if eof and idx >= buf.len: break
  when defined CATCC_LZDBG:
    stderr.writeLine("CATZ lit=", dbgLitZ, " mth=", dbgMthZ, " mlen=", dbgMlenZ)
    for s in 0..<24:
      if dbgNb[s] > 0:
        stderr.writeLine("  nb", s, ": ", dbgNb[s])
    stderr.writeLine("  rep0 hits: ", dbgRepCnt)
  e.rcFlush()
  result = uint64(dst.getPosition() - startOff)

# Adaptive ProbMove + ProbBits: two-stage search, smallest output wins.
# Format: [1 byte header: low4=pmove, high4=pbits][range-coded CAT-Z stream]
proc catZEncode(src, dst: Stream, inputLimit: uint64): uint64 =
  let startOff = dst.getPosition()
  if inputLimit <= 96 * 1024 * 1024:
    var ss = newStringStream()
    ss.write(src.readAll())
    var bestPm = 4
    var bestPb = 15
    var bestOb = 262144
    var bestData = ""
    var bestGreedy = false
    if inputLimit <= 256 * 1024:
      # Small: limited search (2 pmove × 3 pbits = 6 combos)
      for pm in [4, 5]:
        for pb in [11, 13, 15]:
          ss.setPosition(0)
          var tmp = newStringStream()
          discard catZEncodeCore(ss, tmp, inputLimit, pm, pb, 524288, false, true)
          if bestData.len == 0 or tmp.getPosition() < bestData.len.int:
            bestPm = pm; bestPb = pb; bestOb = 524288; bestData = tmp.data; bestGreedy = true
    elif inputLimit <= 4 * 1024 * 1024:
      # Medium: single fast pass with small OptBlock for speed
      ss.setPosition(0)
      var tmp = newStringStream()
      discard catZEncodeCore(ss, tmp, inputLimit, 4, 13, 8192, false, true, 64)
      bestPm = 4; bestPb = 13; bestOb = 8192; bestData = tmp.data; bestGreedy = true
    else:
      # Large (>4MB): single fast pass with good defaults
      ss.setPosition(0)
      var tmp = newStringStream()
      discard catZEncodeCore(ss, tmp, inputLimit, 4, 13, 8192, false, true, 128)
      bestPm = 4; bestPb = 13; bestOb = 8192; bestData = tmp.data
    dst.write uint8(bestPm or (bestPb shl 4))
    dst.write bestData
    result = uint64(dst.getPosition() - startOff)
  else:
    dst.write uint8(4 or (15 shl 4))
    result = uint64(catZEncodeCore(src, dst, inputLimit, 4, 15, 262144, false)) + 1

proc catZDecode(src, dst: Stream, origSize: uint64) =
  var outBuf = ""
  var hist = ""
  var produced: uint64 = 0
  let hdrB = int(src.readUint8())
  let pmove = hdrB and 0xF
  var pbv = hdrB shr 4
  if pbv == 0: pbv = 15
  var d = rcInitD(src, pmove, pbv)
  let pInit = Prob(1 shl (pbv - 1))
  # 12-state LZMA2-style flag machine with position-dependent contexts
  var flagP: array[ZPosStates * 12, Prob]
  for i in 0..<flagP.len: flagP[i] = pInit
  var litU: array[2048 * 256, Prob]
  for i in 0..<litU.len: litU[i] = pInit
  var litM: array[256 * 512, Prob]
  for i in 0..<litM.len: litM[i] = pInit
  # lenP: 4 positions × 8 contexts × 256 (prevLenCls + wasRep selects context)
  var lenP: array[ZPosStates * 8 * 256, Prob]
  for i in 0..<lenP.len: lenP[i] = pInit
  # slotP: 8 contexts × 33 (prevOffsetNbCls selects context)
  var slotP: array[8 * 33, Prob]
  for i in 0..<slotP.len: slotP[i] = pInit
  var lenEP: array[65536, Prob]
  for i in 0..<lenEP.len: lenEP[i] = pInit
  let obMaxBits2 = ZMaxNb
  var obP = newSeq[Prob](1 shl obMaxBits2)
  for i in 0..<obP.len: obP[i] = pInit
  var repP: array[2, Prob]
  for i in 0..<repP.len: repP[i] = pInit
  # selP: 4 positions × 8 contexts
  var selP: array[ZPosStates * 8, Prob]
  for i in 0..<selP.len: selP[i] = pInit
  var reps: array[4, int] = [0, 0, 0, 0]
  var prevLit = 0
  var state = 0
  var prevMatchLen = 0
  var prevOffsetNb = 0
  var prevPrevLit = 0

  proc emit(c: char) =
    if produced >= origSize: fail("アーカイブが破損しています(Z サイズ超過)")
    outBuf.add c
    hist.add c
    if hist.len >= 2 * ZKeepBytes + ChunkSize:
      hist.delete(0 .. ZKeepBytes - 1)
    inc produced
    if outBuf.len >= ChunkSize:
      dst.write outBuf
      outBuf.setLen(0)

  if origSize == 0: return
  while produced < origSize:
    let pos = int(produced) and (ZPosStates - 1)
    let isMatch = rcDecBit(d, flagP[pos * 12 + state])
    if isMatch == 0:
      # LZMA2互換リテラル文脈: lc=3, lp=0, pb=2
      let litCtx = (prevLit shr (8 - Z_LC)) * ZPosStates + pos
      let mctx = prevLit
      var b = 0
      if reps[0] > 0 and produced >= uint64(reps[0]):
        let mbv = int(uint8(hist[len(hist) - reps[0]]))
        var m = 1
        var mb = mbv
        for k in countdown(7, 0):
          let mbit = (mb shr k) and 1
          let sbit = rcDecBit(d, litM[mctx * 512 + (m shl 1) + mbit])
          m = (m shl 1) + sbit
        b = m - 256
      else:
        b = rcTreeDec(d, litU, litCtx * 256, 8)
      emit(char(uint8(b)))
      # LZMA2 state update: literal
      state = if state < 7: 0 else: state - 6
      prevPrevLit = prevLit
      prevLit = b
      prevMatchLen = 0
    else:
      let which = rcTreeDec(d, selP, pos * 8, 3)
      let prevLenCls = if prevMatchLen <= 10: 0
                       elif prevMatchLen <= 40: 1
                       elif prevMatchLen <= 160: 2
                       else: 3
      let lenCtx = prevLenCls * 2 + (if which < 4: 1 else: 0)
      let lenBase = (pos * 8 + lenCtx) * 256
      var lv = rcTreeDec(d, lenP, lenBase, 8)
      if lv == 255:
        lv = 254 + rcTreeDec(d, lenEP, 0, 16)
      let l = lv + 3
      var off = 0
      if which == 4:
        let slotCtx = min(7, prevOffsetNb) * 33
        let nb = rcTreeDec(d, slotP, slotCtx, 5)
        var ov = 0
        if nb > 0:
          var ev = 0
          if nb > 1:
            let bs = zNbBase[nb]
            var m = 0
            for _ in 0..<(nb - 1):
              let bit = rcDecBit(d, obP[bs + m])
              m = (m shl 1) + bit
            ev = m
          ov = (1 shl (nb - 1)) + ev
        off = ov + 1
        prevOffsetNb = nb
      else:
        off = reps[which]
      # LZMA2 state update: match
      if which < 4:
        state = min(state + 1, 11)
      else:
        state = min(state + 3, 11)
      # rep ローテーション (使用した offset を rep0 に昇格)
      if which != 0 and which <= 3:
        let tmp = reps[which]
        for i in countdown(which, 1):
          reps[i] = reps[i-1]
        reps[0] = tmp
      elif which == 4:
        reps[3] = reps[2]; reps[2] = reps[1]; reps[1] = reps[0]; reps[0] = off
      prevMatchLen = l
      if off < 1 or off > hist.len:
        when defined CATCC_LZDBG:
          stderr.writeLine("ZBAD which=", which, " off=", off, " hlen=", hist.len,
                           " produced=", produced, " l=", l)
        fail("アーカイブが破損しています(Z MATCH)")
      # hist は常に 2*WindowSize 以上保持されるため 64KB 参照は安全
      for _ in 0..<l:
        emit(hist[len(hist) - off])
      prevPrevLit = prevLit
      prevLit = int(uint8(hist[len(hist) - 1]))
  if outBuf.len > 0:
    dst.write outBuf

# ---- REV-NN(Tensor): 指数/仮数分離 可逆変換(ZipNN 発想) ----
# 浮動小数点テンソルを「符号+指数バイト列」と「仮数バイト列」に分離する。
# 指数部は強く偏るため CAT-Z(適応範囲符号化)で大幅圧縮され、
# 仮数部も僅かに削減される。復元はバイト完全一致(--safe のテンソル処理)。
const EmMagic = 0x315F4D45.uint32   # "EM_1"

type EmRec = tuple[kind: uint8, blen: int]

proc emAddU64(s: var string, v: uint64) =
  for k in 0..<8:
    s.add char(uint8((v shr (k * 8)) and 0xFF))

proc tensorEMSplit(srcPath: string, cont: var string): bool =
  result = false
  var f: File
  if not f.open(srcPath, fmRead): return
  let sz = getFileSize(srcPath)
  if sz < 16 or sz > 512 * 1024 * 1024: f.close(); return
  var hb = newString(8)
  if f.readBuffer(addr hb[0], 8) != 8: f.close(); return
  var hlen64: uint64 = 0
  for k in 0..<8:
    hlen64 = hlen64 or (uint64(uint8(hb[k])) shl (k * 8))
  if hlen64 < 8.uint64 or hlen64 > 500_000_000.uint64: f.close(); return
  var jsonS = newString(int(hlen64))
  if f.readBuffer(addr jsonS[0], int(hlen64)) != int(hlen64): f.close(); return
  var hdrJ: JsonNode
  try: hdrJ = parseJson(jsonS)
  except CatchableError: f.close(); return
  if hdrJ.kind != JObject: f.close(); return
  var recs: seq[EmRec] = @[]
  var expB = ""
  var manB = ""
  var anyF = false
  let dataBase = 8 + int(hlen64)
  for k, v in hdrJ.pairs:
    if k == "__metadata__": continue
    if v.kind != JObject: f.close(); return
    if v["dtype"].kind != JString: f.close(); return
    if v["data_offsets"].kind != JArray or v["data_offsets"].len < 2: f.close(); return
    let dt = v["dtype"].str
    let st = int(v["data_offsets"][0].getInt(0))
    let en = int(v["data_offsets"][1].getInt(0))
    let blen = en - st
    if blen < 0: f.close(); return
    var esz = 0
    case dt
    of "BF16", "F16": esz = 2
    of "F32": esz = 4
    of "F64": esz = 8
    else: esz = 0
    f.setFilePos(dataBase + st)
    var raw = newString(blen)
    if f.readBuffer(addr raw[0], blen) != blen: f.close(); return
    if esz == 0:
      manB.add raw
      recs.add((1'u8, int(blen)))
      continue
    anyF = true
    var i = 0
    while i + esz <= blen:
      expB.add raw[i + esz - 1]              # 符号+指数バイト(最上位)
      for m in countdown(esz - 2, 0):
        manB.add raw[i + m]
      i += esz
    recs.add((0'u8, int(blen)))
  f.close()
  if not anyF: return
  var c = ""
  c.add char(uint8(EmMagic and 0xFF))
  c.add char(uint8((EmMagic shr 8) and 0xFF))
  c.add char(uint8((EmMagic shr 16) and 0xFF))
  c.add char(uint8((EmMagic shr 24) and 0xFF))
  c.add char(1)                              # version
  emAddU64(c, uint64(jsonS.len))
  c.add jsonS
  emAddU64(c, uint64(recs.len))
  for r in recs:
    c.add char(r.kind)
    emAddU64(c, uint64(r.blen))
  emAddU64(c, uint64(expB.len))
  c.add expB
  c.add manB
  cont = move(c)
  result = true

proc tensorEMReassemble(cont: string, dst: Stream) =
  if cont.len < 24: fail("アーカイブが破損しています(EM先頭)")
  let mg = uint32(uint8(cont[0])) or (uint32(uint8(cont[1])) shl 8) or
           (uint32(uint8(cont[2])) shl 16) or (uint32(uint8(cont[3])) shl 24)
  if mg != EmMagic or uint8(cont[4]) != 1: fail("アーカイブが破損しています(EM magic)")
  var p = 5
  var jlen: uint64 = 0
  for k in 0..<8:
    jlen = jlen or (uint64(uint8(cont[p + k])) shl (k * 8))
  inc(p, 8)
  if p + int(jlen) > cont.len: fail("アーカイブが破損しています(EM json)")
  var jsonS = newString(int(jlen))
  copyMem(addr jsonS[0], unsafeAddr cont[p], int(jlen))
  inc(p, int(jlen))
  var cnt: uint64 = 0
  for k in 0..<8:
    cnt = cnt or (uint64(uint8(cont[p + k])) shl (k * 8))
  inc(p, 8)
  var recs: seq[EmRec] = @[]
  for _ in 0..<cnt:
    let kind = uint8(cont[p]); inc(p)
    var blen: uint64 = 0
    for k in 0..<8:
      blen = blen or (uint64(uint8(cont[p + k])) shl (k * 8))
    inc(p, 8)
    recs.add((kind, int(blen)))
  var expLen: int = 0
  for k in 0..<8:
    expLen = expLen or (int(uint8(cont[p + k])) shl (k * 8))
  inc(p, 8)
  let expAll = cont.substr(p, p + expLen - 1)
  let manAll = cont.substr(p + expLen)
  # ヘッダJSONから dtype/名前を同順で取得
  var hdrJ: JsonNode = parseJson(jsonS)
  type DRec = tuple[dt: string, blen: int]
  var dts: seq[DRec] = @[]
  for k, v in hdrJ.pairs:
    if k == "__metadata__": continue
    dts.add((v["dtype"].str, int(v["data_offsets"][1].getInt(0)) - int(v["data_offsets"][0].getInt(0))))
  if dts.len != recs.len: fail("アーカイブが破損しています(EM count)")
  var ei = 0
  var mi = 0
  var totalB = 0
  for r in recs: totalB += r.blen
  var dataSec = newStringOfCap(totalB + 64)
  for idx in 0..<recs.len:
    let kind = recs[idx].kind
    let blen = recs[idx].blen
    if kind == 1:
      dataSec.add manAll.substr(mi, mi + blen - 1)
      mi += blen
      continue
    let dt = dts[idx].dt
    var esz = 2
    case dt
    of "F32": esz = 4
    of "F64": esz = 8
    else: esz = 2
    let numel = blen div esz
    var ei = 0
    for _ in 0..<numel:
      dataSec.add manAll[mi ..< mi + (esz - 1)]
      mi += esz - 1
      dataSec.add expAll[ei]
      inc ei
  # 出力: u64(len(jsonS)) + json + data
  dst.write uint64(jlen)   # 元のヘッダ長(=jlen)
  dst.write jsonS
  dst.write dataSec

# ---- 差分(--base) 圧縮: 基準モデルとのバイト差分(完全可逆) ----
proc tensorDeltaSplit(curPath, basePath: string, cont: var string,
                      nzOut: var int, totOut: var int): bool =
  result = false
  var fc: File
  if not fc.open(curPath, fmRead): return
  var fb: File
  if not fb.open(basePath, fmRead): fc.close(); return
  let csz = getFileSize(curPath)
  let bsz = getFileSize(basePath)
  if csz < 16 or csz > 512 * 1024 * 1024 or bsz < 16: fc.close(); fb.close(); return
  var ch = newString(8)
  if fc.readBuffer(addr ch[0], 8) != 8: fc.close(); fb.close(); return
  var cjlen: uint64 = 0
  for k in 0..<8:
    cjlen = cjlen or (uint64(uint8(ch[k])) shl (k * 8))
  if cjlen < 8.uint64 or cjlen > 500_000_000.uint64: fc.close(); fb.close(); return
  var cjson = newString(int(cjlen))
  if fc.readBuffer(addr cjson[0], int(cjlen)) != int(cjlen): fc.close(); fb.close(); return
  var bh = newString(8)
  if fb.readBuffer(addr bh[0], 8) != 8: fc.close(); fb.close(); return
  var bjlen: uint64 = 0
  for k in 0..<8:
    bjlen = bjlen or (uint64(uint8(bh[k])) shl (k * 8))
  if bjlen < 8.uint64 or bjlen > 500_000_000.uint64: fc.close(); fb.close(); return
  var bjson = newString(int(bjlen))
  if fb.readBuffer(addr bjson[0], int(bjlen)) != int(bjlen): fc.close(); fb.close(); return
  var cJ: JsonNode
  var bJ: JsonNode
  try:
    cJ = parseJson(cjson); bJ = parseJson(bjson)
  except CatchableError:
    fc.close(); fb.close(); return
  # テンソル対応表(名前一致・dtype一致・numel一致)
  type PairR = tuple[cst: int, blen: int]
  var pairs: seq[PairR] = @[]
  var totalData = 0
  var nzCnt = 0
  block buildPairs:
    for k, v in cJ.pairs:
      if k == "__metadata__": continue
      if v.kind != JObject: break buildPairs
      if not bJ.hasKey(k): break buildPairs
      let bv = bJ[k]
      if bv.kind != JObject: break buildPairs
      if v["dtype"].str != bv["dtype"].str: break buildPairs
      if v["shape"].kind != JArray or bv["shape"].kind != JArray: break buildPairs
      if v["shape"].len != bv["shape"].len: break buildPairs
      var same = true
      for i2 in 0..<v["shape"].len:
        if v["shape"][i2].getInt(0) != bv["shape"][i2].getInt(0): same = false; break
      if not same: break buildPairs
      let st = int(v["data_offsets"][0].getInt(0))
      let en = int(v["data_offsets"][1].getInt(0))
      let bst = int(bv["data_offsets"][0].getInt(0))
      pairs.add((st, en - st))
      # base 側の対応オフセットは別途名前引くため保持しない(下で再検索)
      totalData += en - st
      discard bst
  if pairs.len == 0: fc.close(); fb.close(); return
  # 対応する base オフセットを名前で取得するため再 walk
  type BRec = tuple[name: string, bst: int, blen: int]
  var brecs: seq[BRec] = @[]
  for k, v in bJ.pairs:
    if k == "__metadata__": continue
    let st = int(v["data_offsets"][0].getInt(0))
    let en = int(v["data_offsets"][1].getInt(0))
    brecs.add((k, st, en - st))
  # データ部生成
  var dataSec = newString(totalData)
  let cDataBase = 8 + int(cjlen)
  let bDataBase = 8 + int(bjlen)
  for pr in pairs:
    var written = 0
    let cst = pr.cst
    let blen2 = pr.blen
    # 対応 base tensor を名前×サイズで探す
    var bestB = -1
    for br in brecs:
      if br.blen == blen2 and true:
        bestB = br.bst
        break
    if bestB < 0: fc.close(); fb.close(); return
    const CH2 = 1 shl 22
    var cc = newString(CH2)
    var bb = newString(CH2)
    var pos = 0
    while pos < blen2:
      let take = min(CH2, blen2 - pos)
      fc.setFilePos(cDataBase + cst + pos)
      if fc.readBuffer(addr cc[0], take) != take: fc.close(); fb.close(); return
      fb.setFilePos(bDataBase + bestB + pos)
      if fb.readBuffer(addr bb[0], take) != take: fc.close(); fb.close(); return
      for j in 0..<take:
        cc[j] = char(uint8(cc[j]) - uint8(bb[j]))
        if uint8(cc[j]) != 0: inc nzCnt
      copyMem(addr dataSec[cst + pos], addr cc[0], take)
      written += take
      pos += take
    discard written
  fc.close(); fb.close()
  let baseSha = sha256File(basePath)
  var c = ""
  c.add char(0x44); c.add char(0x54); c.add char(0x31); c.add char(0x00)   # "DT1\0"
  for b in baseSha: c.add char(b)   # base model SHA-256 (32 bytes)
  proc addU64l(s: var string, v: uint64) =
    for k in 0..<8:
      s.add char(uint8((v shr (k * 8)) and 0xFF))
  addU64l(c, uint64(cjson.len))
  c.add cjson
  addU64l(c, uint64(dataSec.len))
  c.add dataSec
  nzOut = nzCnt
  totOut = totalData
  cont = move(c)
  result = true

proc tensorDeltaApply(cont, basePath: string, dst: Stream) =
  if cont.len < 64: fail("アーカイブが破損しています(DELTA先頭)")
  if uint8(cont[0]) != 0x44 or uint8(cont[1]) != 0x54 or uint8(cont[2]) != 0x31:
    fail("アーカイブが破損しています(DELTA magic)")
  var p = 4
  var storedSha: array[32, byte]
  for i in 0..31: storedSha[i] = uint8(cont[p + i])
  inc(p, 32)
  let baseSha = sha256File(basePath)
  if baseSha != storedSha:
    fail("基準モデルのSHA-256が一致しません。アーカイブ作成時に使用した --base と同一のファイルを指定してください。")
  var cjlen: uint64 = 0
  for k in 0..<8:
    cjlen = cjlen or (uint64(uint8(cont[p + k])) shl (k * 8))
  inc(p, 8)
  if p + int(cjlen) > cont.len: fail("アーカイブが破損しています(DELTA json)")
  var cjson = newString(int(cjlen))
  copyMem(addr cjson[0], unsafeAddr cont[p], int(cjlen))
  inc(p, int(cjlen))
  var dlen: uint64 = 0
  for k in 0..<8:
    dlen = dlen or (uint64(uint8(cont[p + k])) shl (k * 8))
  inc(p, 8)
  if p + int(dlen) > cont.len: fail("アーカイブが破損しています(DELTA data)")
  var f: File
  if not f.open(basePath, fmRead): fail("基準モデルを開けません: " & basePath)
  var bh = newString(8)
  if f.readBuffer(addr bh[0], 8) != 8: f.close(); fail("基準モデルが不正です")
  var bjlen: uint64 = 0
  for k in 0..<8:
    bjlen = bjlen or (uint64(uint8(bh[k])) shl (k * 8))
  if bjlen < 8.uint64 or bjlen > 500_000_000.uint64: f.close(); fail("基準モデルが不正です")
  var bjson = newString(int(bjlen))
  if f.readBuffer(addr bjson[0], int(bjlen)) != int(bjlen): f.close(); fail("基準モデル読込失敗")
  var cJ: JsonNode = parseJson(cjson)
  var bJ: JsonNode = parseJson(bjson)
  type BRec2 = tuple[name: string, bst: int, blen: int]
  var brecs: seq[BRec2] = @[]
  for k, v in bJ.pairs:
    if k == "__metadata__": continue
    brecs.add((k, int(v["data_offsets"][0].getInt(0)), int(v["data_offsets"][1].getInt(0))))
  let cDataBase = 8 + int(cjlen)
  let bDataBase = 8 + int(bjlen)
  dst.write uint64(cjlen)
  dst.write cjson
  let dataStart = p
  const CH3 = 1 shl 22
  var dd = newString(CH3)
  var bb = newString(CH3)
  var dataOff = 0
  for k, v in cJ.pairs:
    if k == "__metadata__": continue
    let st = int(v["data_offsets"][0].getInt(0))
    let en = int(v["data_offsets"][1].getInt(0))
    let blen = en - st
    var bestB = -1
    for br in brecs:
      if br.name == k and br.blen == blen:
        bestB = br.bst; break
    if bestB < 0: fail("基準モデルにテンソルがありません: " & k)
    var pos = 0
    while pos < blen:
      let take = min(CH3, blen - pos)
      copyMem(addr dd[0], unsafeAddr cont[dataStart + dataOff], take)
      f.setFilePos(bDataBase + bestB + pos)
      discard f.readBuffer(addr bb[0], take)
      for j in 0..<take:
        dd[j] = char(uint8(dd[j]) + uint8(bb[j]))
      dst.writeData(addr dd[0], take)
      dataOff += take
      pos += take
  f.close()

proc sampleVmRatio(path: string, offset: int64, avail: int64): float =
  var f: File
  if not f.open(path, fmRead): return 1.0
  let want = int(min(int64(SampleSize), avail))
  if want <= 0:
    f.close()
    return 1.0
  f.setFilePos(offset)
  var s = newString(want)
  discard f.readBuffer(addr s[0], want)
  f.close()
  let ss = newStringStream(s)
  let cs = newStringStream()
  let comp = vmEncode(ss, cs, uint64(want))
  result = float(comp) / float(want)

proc sampleLzRatio(path: string, offset: int64, avail: int64): float =
  var f: File
  if not f.open(path, fmRead): return 1.0
  let want = int(min(int64(SampleSize), avail))
  if want <= 0:
    f.close()
    return 1.0
  f.setFilePos(offset)
  var s = newString(want)
  discard f.readBuffer(addr s[0], want)
  f.close()
  let ss = newStringStream(s)
  let cs = newStringStream()
  let comp = lzEncode(ss, cs, uint64(want))
  result = float(comp) / float(want)

# 可逆格納エンジンを選択(内製 CAT-VM / CAT-LZ のサンプル圧縮率比較)。
# 効果が見込めなければ RAW 通過(誠実な圧縮率報告)。
proc sampleZRatio(path: string, offset: int64, avail: int64): float =
  var f: File
  if not f.open(path, fmRead): return 1.0
  let want = int(min(int64(SampleSize), avail))
  if want < 1024:
    f.close(); return 1.0
  f.setFilePos(offset)
  var s = newString(want)
  discard f.readBuffer(addr s[0], want)
  f.close()
  let ss = newStringStream(s)
  let cs = newStringStream("")
  let comp = catZEncode(ss, cs, uint64(want))
  result = float(comp) / float(want)

proc pickReversible(path: string, offset: int64 = 0, avail: int64 = -1): uint8 =
  let a = if avail < 0: int64(getFileSize(path)) else: avail
  if a <= 0: return MethodRaw
  let rv = sampleVmRatio(path, offset, a)
  let rl = sampleLzRatio(path, offset, a)
  let rz = sampleZRatio(path, offset, a)
  when defined CATCC_LZDBG:
    stderr.writeLine("PICK rv=", rv, " rl=", rl, " rz=", rz, " -> ",
                     (if min(min(rv,rl),rz)>=RawThreshold: "RAW"
                      elif rz<=rl and rz<=rv: "Z" elif rl<rv: "LZ" else: "VM"))
  let best = min(min(rv, rl), rz)
  if best >= RawThreshold: return MethodRaw
  if rz <= rl and rz <= rv: return MethodCatZ
  if rl < rv: return MethodCatLz
  result = MethodVm

type BoxInfo = object
  btype: string
  form: uint8
  payloadOff: int64
  payloadLen: int64

proc scanBoxes(path: string): seq[BoxInfo] =
  var f: File
  if not f.open(path, fmRead): return @[]
  let fsz = f.getFileSize()
  var pos: int64 = 0
  while pos < fsz:
    if fsz - pos < 8:
      f.close(); return @[]
    var hdr: array[8, char]
    if f.readBuffer(addr hdr[0], 8) != 8:
      f.close(); return @[]
    let declared = (uint64(uint8(hdr[0])) shl 24) or (uint64(uint8(hdr[1])) shl 16) or
                   (uint64(uint8(hdr[2])) shl 8) or uint64(uint8(hdr[3]))
    var btype = newString(4)
    btype[0] = hdr[4]; btype[1] = hdr[5]; btype[2] = hdr[6]; btype[3] = hdr[7]
    var form: uint8 = 0
    var realLen: uint64 = declared
    var payStart = pos + 8
    if declared == 1:
      if fsz - pos < 16:
        f.close(); return @[]
      var ext: array[8, char]
      if f.readBuffer(addr ext[0], 8) != 8:
        f.close(); return @[]
      realLen = 0
      for k in 0..<8:
        realLen = (realLen shl 8) or uint64(uint8(ext[k]))
      form = 1
      payStart = pos + 16
    elif declared == 0:
      realLen = uint64(fsz - pos)
      form = 2
    let hdrLen = payStart - pos
    if realLen < uint64(hdrLen) or pos + int64(realLen) > fsz:
      f.close(); return @[]
    result.add BoxInfo(btype: btype, form: form, payloadOff: payStart,
                       payloadLen: int64(realLen) - hdrLen)
    pos += int64(realLen)
    f.setFilePos(pos)
    if result.len > 100000:
      f.close(); return @[]
  f.close()
  if result.len == 0 or result[0].btype != "ftyp":
    return @[]

proc isMp4(path: string): bool = scanBoxes(path).len > 0

proc packMp4(srcPath: string, outp: Stream): uint64 =
  let boxes = scanBoxes(srcPath)
  outp.wU32le(uint64(boxes.len))
  var written: uint64 = 4
  for bx in boxes:
    outp.write bx.btype
    outp.write bx.form
    written += 5
    let origBx = uint64(bx.payloadLen)
    outp.wU64le(origBx)
    written += 8
    let compPos = outp.getPosition()
    outp.wU64le(0)
    written += 8
    var mth = MethodRaw
    if bx.payloadLen > 0:
      mth = pickReversible(srcPath, bx.payloadOff, bx.payloadLen)
    outp.write mth
    written += 1
    var compBx = origBx
    case mth
    of MethodRaw:
      echo "  box ", bx.btype, ": RAW保持 ", origBx, " bytes"
      var bf: File
      if not bf.open(srcPath, fmRead): fail("boxの読み込みに失敗: " & srcPath)
      bf.setFilePos(bx.payloadOff)
      let bs = newFileStream(bf)
      copyExact(bs, outp, origBx)
      bs.close()
    of MethodCatLz:
      echo "  box ", bx.btype, ": CAT-LZ変換中..."
      var bf: File
      if not bf.open(srcPath, fmRead): fail("boxの読み込みに失敗: " & srcPath)
      bf.setFilePos(bx.payloadOff)
      let bs = newFileStream(bf)
      compBx = lzEncode(bs, outp, origBx)
      bs.close()
    of MethodVm:
      echo "  box ", bx.btype, ": CAT-VM変換中..."
      var bf: File
      if not bf.open(srcPath, fmRead): fail("boxの読み込みに失敗: " & srcPath)
      bf.setFilePos(bx.payloadOff)
      let bs = newFileStream(bf)
      compBx = vmEncode(bs, outp, origBx)
      bs.close()
    else: discard
    let aft = outp.getPosition()
    outp.setPosition(compPos)
    outp.wU64le(compBx)
    outp.setPosition(aft)
    written += compBx
  result = written

proc unpackMp4(inp: Stream, dst: Stream, expectedComp: uint64) =
  let cnt = inp.rU32le()
  var consumed: uint64 = 4
  for _ in 1..cnt:
    var btype = newString(4)
    if inp.readData(addr btype[0], 4) != 4: fail("アーカイブが破損しています(box)")
    let form = int(inp.rU8())
    let orig = inp.rU64le()
    let comp = inp.rU64le()
    let mth = uint8(inp.rU8())
    consumed += 22
    case form
    of 0:
      if orig + 8 > 0xFFFFFFFF.uint64: fail("MP4再構築エラー: サイズ超過")
      dst.wU32be(orig + 8)
    of 1:
      dst.wU32be(1); dst.wU64be(orig + 16)
    else:
      dst.wU32be(0)
    dst.write btype
    case mth
    of MethodRaw:
      if comp != orig: fail("アーカイブが破損しています(box RAW)")
      copyExact(inp, dst, comp)
    of MethodVm:
      vmDecode(inp, dst, orig)
    of MethodCatLz:
      lzDecode(inp, dst, orig)
    of MethodCatZ:
      catZDecode(inp, dst, orig)
    else:
      fail("アーカイブが破損しています(box method)")
    consumed += comp
  if consumed != expectedComp: fail("アーカイブが破損しています(box合計)")

proc methodName(m: uint8): string =
  case m
  of MethodRaw: "RAW"
  of MethodVm: "CAT-VM"
  of MethodMp4: "MP4"
  of MethodCatLz: "CAT-LZ"
  of MethodJson: "JSON"
  of MethodCatZ: "CAT-Z"
  else: "LOSSY"

const videoExts = [".mp4", ".m4v", ".mov", ".mkv", ".webm", ".avi", ".ts",
                   ".mts", ".m2ts", ".flv", ".wmv", ".mpg", ".mpeg"]
const audioExts = [".wav", ".flac", ".aac", ".m4a", ".mp3", ".ogg", ".opus",
                   ".wma", ".alac", ".ape", ".mid", ".midi"]
const imageExts = [".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".gif",
                   ".webp", ".ico", ".tga", ".ppm", ".pbm"]
const tensorExts = [".safetensors", ".safetensor", ".bin"]
const modelExts = [".obj", ".gltf", ".glb", ".stl", ".fbx", ".blend",
                   ".ply", ".3ds", ".dae", ".wrl", ".x3d", ".usdz", ".usda"]

# ---- 浮動小数点半精度変換 ----
proc f32tof16(x: float32): uint16 =
  let i = cast[uint32](x)
  let sign = (i shr 16) and 0x8000.uint32
  let mant = (i shr 12) and 0x7FF.uint32
  let exp = (i shr 23) and 0xFF.uint32
  if exp == 0xFF.uint32:
    if mant != 0: return 0x7E00.uint16
    return uint16(sign or 0x7C00.uint32)
  var e = int(exp) - 127 + 15
  var m = (i shr 13) and 0x3FF.uint32
  if e <= 0:
    if e < -10: return uint16(sign)
    m = (m or 0x400.uint32) shr uint32(1 - e)
    return uint16(sign or m)
  if e == 0x1F: return uint16(sign or 0x7C00.uint32)
  if (m and 0x1000.uint32) != 0: inc e
  return uint16(sign or (uint32(e) shl 10) or (m and 0x3FF.uint32))

proc rd32(b: seq[byte], o: int): uint32 =
  uint32(b[o]) or (uint32(b[o+1]) shl 8) or
  (uint32(b[o+2]) shl 16) or (uint32(b[o+3]) shl 24)
proc rd64(b: seq[byte], o: int): uint64 =
  uint64(rd32(b, o)) or (uint64(rd32(b, o+4)) shl 32)
proc f16tof32(b: seq[byte], o: int): float32 =
  let h = uint32(b[o]) or (uint32(b[o+1]) shl 8)
  let sign = (h shr 15) and 1.uint32
  let exp = (h shr 10) and 0x1F.uint32
  let mant = h and 0x3FF.uint32
  var f: uint32
  if exp == 0:
    if mant == 0: f = sign shl 31
    else:
      var e = 127 - 15
      var m = mant
      while (m and 0x400.uint32) == 0: m = m shl 1; dec e
      m = m and 0x3FF.uint32
      f = (sign shl 31) or (uint32(e) shl 23) or (m shl 13)
  elif exp == 0x1F:
    f = (sign shl 31) or 0x7F800000.uint32 or (mant shl 13)
  else:
    f = (sign shl 31) or (uint32(exp - 15 + 127) shl 23) or (mant shl 13)
  cast[float32](f)
proc bf16tof32(b: seq[byte], o: int): float32 =
  let h = uint32(b[o]) or (uint32(b[o+1]) shl 8)
  cast[float32](h shl 16)

proc elemBytes(d: string): int =
  case d
  of "F64": 8
  of "F32": 4
  of "F16", "BF16": 2
  of "I64": 8
  of "I32": 4
  of "I16": 2
  else: 1

# ---- 量子化(INT8/INT4) によるテンソル圧縮(非可逆, ストリーミング) ----
# 元の BF16/F16/F32 モデルを INT8(1/2) または INT4(1/4) に量子化し、
# スケールをメタデータに保持。復元時はスケールで逆量子化して BF16 に戻します。
# 一時ファイルを作らず catcomp 出力へ直接ストリーミングするため、
# 空き容量が少ない環境でも安全に動作します。

proc f32toBf16(x: float32): uint16 =
  let i = cast[uint32](x)
  uint16((i shr 16) and 0xFFFF.uint32)

proc elemF32(chunk: seq[byte], so: int, dtype: string): float32 =
  case dtype
  of "F32": cast[float32](rd32(chunk, so))
  of "F64": float32(cast[float64](rd64(chunk, so)))
  of "F16": f16tof32(chunk, so)
  of "BF16": bf16tof32(chunk, so)
  else: 0.float32

proc tensorMaxAbs(srcPath: string, bufStart, tstart, tend: int, dtype: string): float32 =
  var f = openFileStream(srcPath, fmRead)
  f.setPosition(bufStart + tstart)
  let total = tend - tstart
  let eb = elemBytes(dtype)
  var remaining = total
  var chunk = newSeq[byte](1 shl 22)
  var mx = 0.float32
  while remaining > 0:
    let take = min(remaining, chunk.len)
    if f.readData(addr chunk[0], take) != take: break
    let ne = take div eb
    for i in 0..<ne:
      let v = elemF32(chunk, i * eb, dtype)
      let a = if v < 0: -v else: v
      if a > mx: mx = a
    remaining -= take
  f.close()
  mx

# ---- JSON 構造化変換(完全可逆・カラムナ分割) ----
proc u32leStr(v: uint32): string =
  result = newString(4)
  result[0] = char(uint8(v and 0xFF))
  result[1] = char(uint8((v shr 8) and 0xFF))
  result[2] = char(uint8((v shr 16) and 0xFF))
  result[3] = char(uint8((v shr 24) and 0xFF))


# 文字列「内容」をスケルトンから切り離し、キー辞書/文字列値の2ストリームへ分離。
# スケルトン上の各文字列は `"\x01"` プレースホルダになりアルファベットが極端に狭く、
# LZ 後段で劇的に圧縮される。各内容は [u32le 長][バイト列] で保存され、
# 復元はバイト完全一致。不正 JSON 等は false を返し汎用経路へフォールバック。
proc jsonSplit(srcPath: string,
               outSkel, outKeys, outStrs: var string): bool =
  result = false
  var f: File
  if not f.open(srcPath, fmRead): return
  let sz = getFileSize(srcPath)
  if sz < 8 or sz > 1024 * 1024 * 1024: f.close(); return
  var buf = newString(sz)
  if f.readBuffer(addr buf[0], sz) != sz: f.close(); return
  f.close()
  var skel = ""
  var keys = ""
  var strs = ""
  var cur = ""
  var inStr = false
  var depth = 0
  var anyStr = false
  var i = 0
  while i < sz:
    let c = buf[i]
    if inStr:
      if c == '\\':
        if i + 1 >= sz: return
        cur.add c; cur.add buf[i+1]
        i += 2
        continue
      if c == '"':
        # 直後の非空白が ':' ならキー(復元側と同一規則)
        var j = i + 1
        while j < sz and (buf[j] == ' ' or buf[j] == '\t' or buf[j] == '\n' or buf[j] == '\r'): inc j
        let isKeyEntry = (j < sz and (buf[j] == ':' or buf[j] == '{' or buf[j] == '['))
        let ln = uint32(cur.len)
        if isKeyEntry:
          keys.add u32leStr(ln); keys.add cur
        else:
          strs.add u32leStr(ln); strs.add cur
        cur.setLen(0)
        inStr = false
        skel.add '"'
        i += 1
        continue
      if ord(c) < 0x20: return
      cur.add c
      i += 1
      continue
    case c
    of '"':
      inStr = true
      anyStr = true
      cur.setLen(0)
      skel.add '"'
      skel.add '\x01'
      i += 1
    of '{', '[':
      inc depth
      if depth > 512: return
      skel.add c; i += 1
    of '}':
      if depth == 0: return
      dec depth
      skel.add c; i += 1
    of ']':
      if depth == 0: return
      dec depth
      skel.add c; i += 1
    of ',':
      if depth == 0: return
      skel.add c; i += 1
    of ':':
      if depth == 0: return
      skel.add c; i += 1
    of ' ', '\t', '\n', '\r':
      skel.add c; i += 1
    else:
      if ord(c) < 0x20 or ord(c) > 0x7e: return
      skel.add c; i += 1
  if inStr or depth != 0: return
  if not anyStr: return
  outSkel = move(skel)
  outKeys = move(keys)
  outStrs = move(strs)
  result = true

proc jsonReassemble(skel, keys, strs: string, origSize: int64, dst: Stream) =
  var ki = 0
  var si = 0
  var produced = 0
  var buf = ""
  proc flush() =
    if buf.len > 0:
      dst.write buf
      produced += buf.len
      buf.setLen(0)
  var i = 0
  let n = skel.len
  while i < n:
    let c = skel[i]
    if c == '"':
      if not (i + 2 < n and skel[i+1] == '\x01' and skel[i+2] == '"'):
        fail("アーカイブが破損しています(JSONマーカ)")
      var j = i + 3
      while j < n and (skel[j] == ' ' or skel[j] == '\t' or skel[j] == '\n' or skel[j] == '\r'):
        inc j
      let isKey = (j < n and (skel[j] == ':' or skel[j] == '{' or skel[j] == '['))
      buf.add '"'            # 開き引用符
      var ln: int
      if isKey:
        if ki + 4 > keys.len: fail("アーカイブが破損しています(JSON keys長)")
        ln = int(uint8(keys[ki])) or (int(uint8(keys[ki+1])) shl 8) or
             (int(uint8(keys[ki+2])) shl 16) or (int(uint8(keys[ki+3])) shl 24)
        inc(ki, 4)
        if ki + ln > keys.len: fail("アーカイブが破損しています(JSON keys)")
        buf.add substr(keys, ki, ki + ln - 1)
        inc(ki, ln)
      else:
        if si + 4 > strs.len: fail("アーカイブが破損しています(JSON strs長)")
        ln = int(uint8(strs[si])) or (int(uint8(strs[si+1])) shl 8) or
             (int(uint8(strs[si+2])) shl 16) or (int(uint8(strs[si+3])) shl 24)
        inc(si, 4)
        if si + ln > strs.len: fail("アーカイブが破損しています(JSON strs)")
        buf.add substr(strs, si, si + ln - 1)
        inc(si, ln)
      buf.add '"'
      i += 3
      if buf.len >= 1 shl 20: flush()
      continue
    buf.add c
    i += 1
    if buf.len >= 1 shl 20: flush()
  flush()
  when defined CATCC_LZDBG:
    stderr.writeLine("DBGREASM produced=", produced, " orig=", origSize,
                     " ki=", ki, "/", keys.len, " si=", si, "/", strs.len)
  if produced != origSize: fail("アーカイブが破損しています(JSON サイズ)")

# ---- テンソル量子化ヘルパ(候補試算はヘッダ組立のみで完結・データ再読込なし) ----
type QuantInfo = tuple[name: string, dtype: string, start: int, en: int, numel: int, shape: seq[int]]

proc quantMaxAbsAll(srcPath: string, infos: seq[QuantInfo], bufStart: int): seq[float32] =
  result = newSeq[float32](infos.len)
  for i, t in infos:
    if t.dtype in ["F32", "F64", "F16", "BF16"]:
      result[i] = tensorMaxAbs(srcPath, bufStart, t.start, t.en, t.dtype)

proc quantRenderScales(infos: seq[QuantInfo], maxAbs: seq[float32], bits: int): JsonNode =
  result = newJObject()
  let rng = if bits == 4: 7.0.float32 else: 127.0.float32
  for i, t in infos:
    if t.dtype in ["F32", "F64", "F16", "BF16"]:
      let mx = maxAbs[i]
      let sc = if mx <= 0.float32: 1.0.float32 else: mx / rng
      result[t.name] = newJFloat(float(sc))

proc quantBuildHeader(infos: seq[QuantInfo], meta: JsonNode,
                      maxAbs: seq[float32], bits: int): tuple[nhs: string, pos: int] =
  var obj = newJObject()
  if meta != nil: obj["__metadata__"] = meta
  if not obj.hasKey("__metadata__"): obj["__metadata__"] = newJObject()
  var qm = newJObject()
  qm["bits"] = newJInt(int64(bits))
  qm["scales"] = quantRenderScales(infos, maxAbs, bits)
  # 復元時に入力時と同じ dtype へ戻すため、元の精度を記録する
  var origD = newJObject()
  for t in infos:
    if t.dtype in ["F32", "F64", "F16", "BF16"]:
      origD[t.name] = newJString(t.dtype)
  qm["orig"] = origD
  obj["__metadata__"]["__quant__"] = qm
  var p = 0
  for t in infos:
    var nd = newJObject()
    var sa = newJArray()
    for s in t.shape: sa.add(newJInt(int64(s)))
    nd["shape"] = sa
    let isF = t.dtype in ["F32", "F64", "F16", "BF16"]
    var od: string
    var ob: int
    if isF:
      od = if bits == 4: "I4" elif bits == 8: "I8" else: "F16"
      ob = if od == "I8": t.numel elif od == "I4": (t.numel + 1) div 2 else: t.numel * 2
    else:
      od = t.dtype
      ob = t.numel * elemBytes(t.dtype)
    var doffs = newJArray()
    doffs.add(newJInt(int64(p)))
    doffs.add(newJInt(int64(p + ob)))
    nd["data_offsets"] = doffs
    nd["dtype"] = newJString(od)
    obj[t.name] = nd
    p += ob
  result = ($obj, p)

# 逆量子化した値を元の dtype 精度で書き出す
proc writeDequant(outp: Stream, val: float32, od: string) =
  case od
  of "F32":
    let u = cast[uint32](val)
    outp.write uint8(u and 0xFF)
    outp.write uint8((u shr 8) and 0xFF)
    outp.write uint8((u shr 16) and 0xFF)
    outp.write uint8((u shr 24) and 0xFF)
  of "F64":
    let d = float64(val)
    let u = cast[uint64](d)
    for k in 0.uint64..<8.uint64:
      outp.write uint8(uint64((u shr (k * 8.uint64)) and 0xFF))
  of "F16":
    let hh = f32tof16(val)
    outp.write uint8(hh and 0xFF)
    outp.write uint8((hh shr 8) and 0xFF)
  else:  # BF16(既定・後方互換)
    let hh = f32toBf16(val)
    outp.write uint8(hh and 0xFF)
    outp.write uint8((hh shr 8) and 0xFF)

# 量子化した safetensors を、catcomp のエントリごと直接書き出す(一時ファイル不要)。
# qbits=0(auto)は FP16/INT8/INT4 を試算し、実出力が最小のビット数を採用する
# (同サイズなら高品質側を優先)。max-abs は 1 パスで計算し全候補で再利用。
# 成功時は (lossy ペイロード compSize, 採用 bits)、不適時は (0, 0) を返します。
proc packTensorQuant(outp: Stream, kind: uint8, relPath: string,
                     srcPath: string, origF: uint64, qbits: int): tuple[compL: uint64, bits: int] =
  if origF < 16: return (0.uint64, 0)  # safetensorsヘッダ(8B長+JSON)に満たない場合は対象外
  var f = openFileStream(srcPath, fmRead)
  if f.atEnd(): f.close(); return (0.uint64, 0)
  let rawHlen = f.rU64le()
  if rawHlen == 0.uint64 or rawHlen > 500_000_000.uint64: f.close(); return (0.uint64, 0)
  let hlen = int(rawHlen)
  var hdrBytes = newString(hlen)
  if f.readData(addr hdrBytes[0], hlen) != hlen: f.close(); return (0.uint64, 0)
  var hdr: JsonNode
  try: hdr = parseJson(hdrBytes)
  except: f.close(); return (0.uint64, 0)
  var infos: seq[QuantInfo] = @[]
  var meta: JsonNode = nil
  for k, v in hdr.pairs:
    if k == "__metadata__": meta = v; continue
    if v.kind != JObject: continue
    if v["dtype"].kind != JString: continue
    if v["data_offsets"].kind != JArray or v["data_offsets"].len < 2: continue
    let dtype = v["dtype"].str
    let st = int(v["data_offsets"][0].getInt(0))
    let en = int(v["data_offsets"][1].getInt(0))
    var shp: seq[int] = @[]
    var numel = 1
    if v.hasKey("shape") and v["shape"].kind == JArray:
      for s in v["shape"]:
        let x = int(s.getInt(0)); shp.add(x); numel *= x
    infos.add((k, dtype, st, en, numel, shp))
  infos.sort(proc(a, b: QuantInfo): int = cmp(a.start, b.start))
  let bufStart = 8 + hlen
  # pass1: 最大絶対値を一度だけ計算(全候補で再利用)
  let maxAbs = quantMaxAbsAll(srcPath, infos, bufStart)
  # 候補試算 → 実出力最小を採用(同点は高品質側=先に評価した側を維持)
  var cands: seq[int] = @[]
  if qbits == 0: cands = @[16, 8, 4] else: cands = @[qbits]
  var bestBits = cands[0]
  var bestNhs = ""
  var bestPos = 0
  var bestProd = high(int64)
  for b in cands:
    let (nhs, p) = quantBuildHeader(infos, meta, maxAbs, b)
    let prod = 8'i64 + int64(nhs.len) + int64(p)
    if prod < bestProd:
      bestProd = prod; bestBits = b; bestNhs = nhs; bestPos = p
  # 厳密な削減判定。不適なら何も書かずに戻る(呼び出し側は可逆へフォールバック)
  if bestProd >= int64(origF):
    f.close(); return (0.uint64, 0)
  # エントリ構築: 量子化本文を一旦シンクへ書き出しし、
  # RAW / CAT-LZ / CAT-Z の最小を採用してから格納する(エントロピー段)
  let ext = "safetensors"
  let produced = bestProd
  var sink: Stream
  var sinkFile = ""
  if produced <= 64 * 1024 * 1024:
    sink = newStringStream("")
  else:
    sinkFile = ccTmpDir() & "/catcc_" & $getCurrentProcessId() & "_qtensor"
    sink = openFileStream(sinkFile, fmWrite)
  let sinkStart = sink.getPosition()
  # 量子化済み safetensors のヘッダもシンクへ(8byte長+JSON)
  sink.write uint64(bestNhs.len)
  sink.write bestNhs

  # pass2: 実データをストリーミング量子化してシンクへ書き出し
  const CH = 1 shl 22
  var chunk = newSeq[byte](CH)
  let rngC = if bestBits == 4: 7.0.float32 else: 127.0.float32
  for i, t in infos:
    let isFloat = (t.dtype in ["F32", "F64", "F16", "BF16"])
    let inLen = t.en - t.start
    if inLen <= 0: continue
    let eb = elemBytes(t.dtype)
    f.setPosition(bufStart + t.start)
    var remaining = inLen
    if not isFloat:
      while remaining > 0:
        let take = min(remaining, CH)
        if f.readData(addr chunk[0], take) != take: f.close(); return (0.uint64, 0)
        sink.write(cast[string](chunk[0..<take]))
        remaining -= take
    elif bestBits == 8:
      let mx = maxAbs[i]
      let sc = if mx <= 0.float32: 1.0.float32 else: mx / rngC
      while remaining > 0:
        let take = min(remaining, CH)
        if f.readData(addr chunk[0], take) != take: f.close(); return (0.uint64, 0)
        let ne = take div eb
        for j in 0..<ne:
          let v = elemF32(chunk, j * eb, t.dtype)
          var qq = int(round(float(v) / float(sc)))
          if qq > 127: qq = 127
          if qq < -127: qq = -127
          sink.write uint8(if qq < 0: qq + 256 else: qq)
        remaining -= take
    elif bestBits == 4:
      let mx = maxAbs[i]
      let sc = if mx <= 0.float32: 1.0.float32 else: mx / rngC
      while remaining > 0:
        let take = min(remaining, CH)
        if f.readData(addr chunk[0], take) != take: f.close(); return (0.uint64, 0)
        let ne = take div eb
        var j = 0
        while j < ne:
          let v0 = elemF32(chunk, j * eb, t.dtype)
          var q0 = int(round(float(v0) / float(sc)))
          if q0 > 7: q0 = 7
          if q0 < -7: q0 = -7
          j += 1
          if j < ne:
            let v1 = elemF32(chunk, j * eb, t.dtype)
            var q1 = int(round(float(v1) / float(sc)))
            if q1 > 7: q1 = 7
            if q1 < -7: q1 = -7
            j += 1
            sink.write uint8((uint8(q0 and 0xF)) or (uint8(q1 and 0xF) shl 4))
          else:
            sink.write uint8(uint8(q0 and 0xF))
        remaining -= take
    else:
      while remaining > 0:
        let take = min(remaining, CH)
        if f.readData(addr chunk[0], take) != take: f.close(); return (0.uint64, 0)
        let ne = take div eb
        for j in 0..<ne:
          let v = elemF32(chunk, j * eb, t.dtype)
          let hh = f32tof16(v)
          sink.write uint8(hh and 0xFF)
          sink.write uint8((hh shr 8) and 0xFF)
        remaining -= take
  f.close()
  when defined CATCC_LZDBG:
    stderr.writeLine("SINKLEN=", sink.getPosition() - sinkStart, " produced=", produced)
  # --- エントロピー段: RAW / CAT-LZ / CAT-Z の最小を採用 ---
  var msRaw = newStringStream()
  sink.setPosition(sinkStart)
  copyExact(sink, msRaw, uint64(produced))
  var msLzS = newStringStream()
  sink.setPosition(sinkStart)
  let nLz = lzEncode(sink, msLzS, uint64(produced))
  var msZS = newStringStream()
  sink.setPosition(sinkStart)
  let nZ = catZEncode(sink, msZS, uint64(produced))
  when defined CATCC_LZDBG:
    stderr.writeLine("ENTSZ raw=", produced, " lz=", nLz, " z=", nZ)
  var chosenInner = MethodRaw
  var chosenStream: Stream = msRaw
  var chosenSize = uint64(produced)
  when not defined CATCC_RAWTENSOR:
    if nLz > 0 and uint64(nLz) < chosenSize:
      chosenInner = MethodCatLz; chosenStream = msLzS; chosenSize = uint64(nLz)
    if nZ > 0 and uint64(nZ) <= chosenSize:
      chosenInner = MethodCatZ; chosenStream = msZS; chosenSize = uint64(nZ)
  let compL = uint64(1 + ext.len + 1 + 8 + int(chosenSize))
  outp.write kind
  outp.write uint8(relPath.len); outp.write relPath
  outp.write MethodLossy
  outp.wU64le(origF)
  outp.wU64le(compL)
  outp.write uint8(ext.len); outp.write ext
  outp.write chosenInner
  outp.wU64le(uint64(produced))          # transSize = 量子化済み safetensors 原寸
  outp.wU64le(chosenSize)                # 圧縮後サイズ
  chosenStream.setPosition(0)
  copyExact(chosenStream, outp, chosenSize); entryCsumWrite(outp, 0, 0)
  if sinkFile != "":
    try: removeFile(sinkFile)
    except CatchableError: discard
  result = (compL, bestBits)

# 量子化済み safetensors ペイロードを読み、
#   - 量子化済み(I8/I4)ならスケールで逆量子化して BF16 に復元
#   - それ以外(例: 旧fp16)ならそのままコピー
# transSize バイトちょうどを inp から消費します。
proc restoreTensorPayload(inp: Stream, outp: Stream, transSize: uint64) =
  let hlen = int(inp.rU64le())
  var hdrBytes = newString(hlen)
  if inp.readData(addr hdrBytes[0], hlen) != hlen:
    fail("アーカイブが破損しています(テンソルヘッダ)")
  var hdr: JsonNode
  try: hdr = parseJson(hdrBytes)
  except: fail("アーカイブが破損しています(テンソルJSON)")
  type TInfo = tuple[name: string, dtype: string, numel: int, start: int]
  var infos: seq[TInfo] = @[]
  var scales: JsonNode = nil
  var origD: JsonNode = nil
  if hdr.hasKey("__metadata__") and hdr["__metadata__"].hasKey("__quant__"):
    let q = hdr["__metadata__"]["__quant__"]
    scales = q["scales"]
    # 入力時の dtype(旧アーカイブに無い場合は BF16 扱いで後方互換)
    if q.hasKey("orig") and q["orig"].kind == JObject:
      origD = q["orig"]
  for k, v in hdr.pairs:
    if k == "__metadata__": continue
    if v.kind != JObject or v["dtype"].kind != JString: continue
    if v["data_offsets"].kind != JArray: continue
    let dtype = v["dtype"].str
    let st = int(v["data_offsets"][0].getInt(0))
    var numel = 1
    if v.hasKey("shape") and v["shape"].kind == JArray:
      for s in v["shape"]: numel *= int(s.getInt(0))
    infos.add((k, dtype, numel, st))
  infos.sort(proc(a, b: TInfo): int = cmp(a.start, b.start))
  let isQuant = (scales != nil)
  if not isQuant:
    outp.wU64le(uint64(hlen))
    outp.write hdrBytes
    let remaining = int64(transSize) - 8 - int64(hlen)
    if remaining > 0: copyExact(inp, outp, uint64(remaining))
    return
  var newObj = newJObject()
  if hdr.hasKey("__metadata__"): newObj["__metadata__"] = hdr["__metadata__"]
  var pos = 0
  for t in infos:
    var nd = newJObject()
    var shpArr = newJArray()
    if hdr[t.name].hasKey("shape"):
      for s in hdr[t.name]["shape"]: shpArr.add(newJInt(int64(s.getInt(0))))
    nd["shape"] = shpArr
    let isQ = (t.dtype == "I8" or t.dtype == "I4")
    let outDtype =
      if isQ:
        if origD != nil and origD.hasKey(t.name): origD[t.name].getStr("BF16")
        else: "BF16"
      else: t.dtype
    let outBytes = t.numel * elemBytes(outDtype)
    let doffs = newJArray()
    doffs.add(newJInt(int64(pos)))
    doffs.add(newJInt(int64(pos + outBytes)))
    nd["data_offsets"] = doffs
    nd["dtype"] = newJString(outDtype)
    newObj[t.name] = nd
    pos += outBytes
  let nhs = $newObj
  outp.wU64le(uint64(nhs.len))
  outp.write nhs
  const CH = 1 shl 22
  var chunk = newSeq[byte](CH)
  for t in infos:
    let isQ = (t.dtype == "I8" or t.dtype == "I4")
    if not isQ:
      let eb = elemBytes(t.dtype)
      var l = t.numel * eb
      while l > 0:
        let take = min(l, CH)
        if inp.readData(addr chunk[0], take) != take: fail("アーカイブが破損しています(テンソル復元)")
        outp.write(cast[string](chunk[0..<take]))
        l -= take
    elif t.dtype == "I8":
      let outDtype =
        if origD != nil and origD.hasKey(t.name): origD[t.name].getStr("BF16")
        else: "BF16"
      let sc = if scales.hasKey(t.name): float32(float(scales[t.name].getFloat(1.0))) else: 1.0.float32
      var l = t.numel
      while l > 0:
        let take = min(l, CH)
        if inp.readData(addr chunk[0], take) != take: fail("アーカイブが破損しています(テンソル復元)")
        for i in 0..<take:
          let b = int(chunk[i])
          let sv = if b >= 128: b - 256 else: b
          let val = float(sv) * float(sc)
          writeDequant(outp, float32(val), outDtype)
        l -= take
    else:
      let outDtype =
        if origD != nil and origD.hasKey(t.name): origD[t.name].getStr("BF16")
        else: "BF16"
      let sc = if scales.hasKey(t.name): float32(float(scales[t.name].getFloat(1.0))) else: 1.0.float32
      var l = t.numel
      while l > 0:
        let take = min(l, CH)
        let rbytes = (take + 1) div 2
        if inp.readData(addr chunk[0], rbytes) != rbytes: fail("アーカイブが破損しています(テンソル復元)")
        for i in 0..<take:
          let bi = i div 2
          let nib = if (i and 1) == 0: int(chunk[bi]) and 0xF else: (int(chunk[bi]) shr 4) and 0xF
          let sv = if nib >= 8: nib - 16 else: nib
          let val = float(sv) * float(sc)
          writeDequant(outp, float32(val), outDtype)
        l -= take

# 3D モデル(.obj) の頂点座標を丸めて軽量化(非可逆)
proc roundObj(srcPath: string, q: int): tuple[tmp, ext: string] =
  result = ("", "")
  let dec = max(1, min(6, int(round(float(51 - q) / 10.0)) + 1))
  var f = openFileStream(srcPath, fmRead)
  let content = f.readAll()
  f.close()
  let tmp = ccTmpDir() & "/catcc_" & $getCurrentProcessId() & "_model.obj"
  var outp = openFileStream(tmp, fmWrite)
  for line in content.splitLines():
    var outLine = line
    let sp = line.split(' ')
    if sp.len >= 2 and (sp[0] == "v" or sp[0] == "vn" or sp[0] == "vt"):
      var parts: seq[string] = @[sp[0]]
      for k in 1..<sp.len:
        let t = sp[k]
        if t.len == 0: continue
        try:
          let v = parseFloat(t)
          parts.add(formatFloat(v, ffDecimal, dec))
        except:
          parts.add(t)
      outLine = parts.join(" ")
    outp.write outLine
    outp.write "\n"
  outp.close()
  result = (tmp, "obj")

proc lossyCategory(path: string): string =
  let ext = toLowerAscii(splitFile(path).ext)
  if ext in videoExts or isMp4(path): return "video"
  if ext in imageExts: return "image"
  if ext in audioExts: return "audio"
  if ext in tensorExts: return "tensor"
  if ext in modelExts: return "model"
  return ""

# q: 品質パラメータ (0=高品質/大きい … 51=最小/最圧縮)
proc tryTranscode(srcPath: string, q: int): tuple[tmp, ext, label: string] =
  result = ("", "", "")
  let cat = lossyCategory(srcPath)
  if cat == "": return
  let pid = $getCurrentProcessId()
  case cat
  of "video":
    if findExe("ffmpeg") == "": return
    let tmp = ccTmpDir() & "/catcc_" & pid & "_video.mp4"
    let cmd = "ffmpeg -y -v error -i \"" & srcPath & "\"" &
              " -map 0:v:0 -map \"0:a:0?\"" &
              " -c:v libx264 -crf " & $q & " -preset veryfast -pix_fmt yuv420p" &
              " -c:a aac -b:a 48k -movflags +faststart \"" & tmp & "\" > /dev/null 2>&1"
    if execShellCmd(cmd) == 0 and getFileSize(tmp) > 0:
      result = (tmp, "mp4", "VIDEO")
    else:
      if fileExists(tmp): removeFile(tmp)
  of "image":
    if findExe("ffmpeg") == "": return
    let tmp = ccTmpDir() & "/catcc_" & pid & "_image.webp"
    let cmd = "ffmpeg -y -v error -i \"" & srcPath & "\" -q:v " & $q &
              " \"" & tmp & "\" > /dev/null 2>&1"
    if execShellCmd(cmd) == 0 and getFileSize(tmp) > 0:
      result = (tmp, "webp", "IMAGE")
    else:
      if fileExists(tmp): removeFile(tmp)
  of "audio":
    if findExe("ffmpeg") == "": return
    let tmp = ccTmpDir() & "/catcc_" & pid & "_audio.opus"
    let br = max(32, (51 - q) * 2 + 48)
    let cmd = "ffmpeg -y -v error -i \"" & srcPath & "\" -c:a libopus -b:a " & $br & "k \"" & tmp & "\" > /dev/null 2>&1"
    if execShellCmd(cmd) == 0 and getFileSize(tmp) > 0:
      result = (tmp, "opus", "AUDIO")
    else:
      if fileExists(tmp): removeFile(tmp)
  of "tensor":
    # テンソル量子化は packEntry のファストパス(packTensorQuant)で処理します。
    # ここでは何もせず呼び出し側の可逆フォールバックへ任せます。
    discard
  of "model":
    if toLowerAscii(splitFile(srcPath).ext) == ".obj":
      let (t, e) = roundObj(srcPath, q)
      if t != "": result = (t, e, "MODEL")

proc packEntry(outp: Stream, kind: uint8, relPath, srcPath, dispName: string,
               rawCount: var int, vmCount: var int, mp4Count: var int,
               lossyCount: var int, lzCount: var int, zCount: var int, revCount: var int,
               totOrig: var uint64, totComp: var uint64,
               lossy: bool, q: int, qbits: int, baseP: string, safeAi = false,
               skelJsonCache: var string, keysJsonCache: var string, strsJsonCache: var string,
               skelOrigCache: var uint64, keysOrigCache: var uint64, strsOrigCache: var uint64) =
  let origF = getFileSize(srcPath)
  if relPath.len > 255: fail("パスが長すぎます(255byte以内): " & relPath)
  # 可逆エントリ用の原文CRC32C(初回使用時のみ計算。非可逆変換はスキップ対象)
  var srcCrc = 0.uint32
  var srcCrcSet = false
  proc needSrcCrc(): uint32 =
    if not srcCrcSet:
      srcCrc = crc32cFile(srcPath)
      srcCrcSet = true
    srcCrc

  # --- 差分(--base) ファストパス: 基準モデルとのバイト差分を可逆格納 ---
  if baseP != "" and origF >= 4096 and origF <= 512 * 1024 * 1024 and
     lossyCategory(srcPath) == "tensor" and fileExists(baseP):
    var dCont = ""
    var dNz = 0
    var dTot = 0
    if tensorDeltaSplit(srcPath, baseP, dCont, dNz, dTot) and
       (dTot == 0 or dNz * 100 < dTot * 12):
      # 変化バイトが一割未満のときだけ差分を採用(それ以外は量子化へ)
      var msZ = newStringStream(dCont)
      var tmpO = newStringStream("")
      let nZ = catZEncode(msZ, tmpO, uint64(dCont.len))
      tmpO.setPosition(0)
      let zdata = tmpO.readAll()
      outp.write kind
      outp.write uint8(relPath.len); outp.write relPath
      outp.write MethodLossy
      outp.wU64le(uint64(origF))
      let compPos = outp.getPosition(); outp.wU64le(0)
      let payStart = outp.getPosition()
      let extS = "dtens"
      outp.write uint8(extS.len); outp.write extS
      outp.write MethodCatZ
      outp.wU64le(uint64(dCont.len))
      let iph = outp.getPosition(); outp.wU64le(0)
      outp.write zdata
      let aft = outp.getPosition()
      let dataComp = uint64(aft - iph - 8)
      outp.setPosition(iph); outp.wU64le(dataComp)
      let compL = uint64(aft - payStart)
      outp.setPosition(compPos); outp.wU64le(compL); outp.setPosition(aft); entryCsumWrite(outp, 1, needSrcCrc())
      inc revCount
      let pct = 100.0 - float(compL) / float(origF) * 100.0
      echo "追加: ", dispName, " [REV-DELTA vs ", extractFilename(baseP), "] ",
           origF, " → ", compL, " bytes (", pct.formatFloat(ffDecimal, 1), "%削減・可逆)"
      totOrig += uint64(origF)
      totComp += compL + uint64(22 + relPath.len)
      return

  # --- JSON 構造化変換: スケルトン/キー/値分離でテキスト圧縮を大幅改善(1MB以下のみ) ---
  if origF >= 512 and origF <= 1 * 1024 * 1024 and srcPath.toLowerAscii.endsWith(".json"):
    var skel, keys, strs: string
    if jsonSplit(srcPath, skel, keys, strs):
      var inner = newStringStream("")
      inner.wU64le(uint64(skel.len))
      inner.wU64le(uint64(keys.len))
      inner.wU64le(uint64(strs.len))
      inner.write(skel)
      inner.write(keys)
      inner.write(strs)
      let innerData = inner.data
      var msZ = newStringStream(innerData)
      var tmpOut = newStringStream("")
      tmpOut.write uint8(4 or (13 shl 4))
      discard catZEncodeCore(msZ, tmpOut, uint64(innerData.len), 4, 13, 8192, false, true, 256)
      tmpOut.setPosition(0)
      let zdata = tmpOut.readAll()
      let useMth = MethodCatZ
      if zdata.len + 24 < int(float(origF) * 0.95):
        outp.write kind
        outp.write uint8(relPath.len); outp.write relPath
        outp.write MethodLossy
        outp.wU64le(uint64(origF))
        let compPos = outp.getPosition(); outp.wU64le(0)
        let payStart = outp.getPosition()
        let extS = "json"
        outp.write uint8(extS.len); outp.write extS
        outp.write useMth
        outp.wU64le(uint64(innerData.len))
        let iph = outp.getPosition(); outp.wU64le(0)
        outp.write zdata
        let aft = outp.getPosition()
        let dataComp = uint64(aft - iph - 8)
        outp.setPosition(iph); outp.wU64le(dataComp)
        let compL = uint64(aft - payStart)
        outp.setPosition(compPos); outp.wU64le(compL); outp.setPosition(aft); entryCsumWrite(outp, 1, needSrcCrc())
        inc revCount
        let pct = 100.0 - float(compL) / float(origF) * 100.0
        echo "追加: ", dispName, " [REV-JSON(可逆)] ", origF, " → ", compL, " bytes (", pct.formatFloat(ffDecimal, 1), "%削減)"
        totOrig += uint64(origF)
        totComp += compL + uint64(22 + relPath.len)
        return

  # --- BWT 可逆変換(テキスト用) ---
  if origF >= 1024 and origF <= 4 * 1024 * 1024 and
     (srcPath.toLowerAscii.endsWith(".txt") or srcPath.toLowerAscii.endsWith(".csv") or
       srcPath.toLowerAscii.endsWith(".log")):
    var fB: File
    if fB.open(srcPath, fmRead):
      var txt = newString(int(origF))
      let gotB = fB.readBuffer(addr txt[0], int(origF))
      fB.close()
      if gotB == int(origF):
        let (bwtData, prim) = bwtEncode(txt)
        var innerB = newString(4 + bwtData.len)
        innerB[0] = char(prim and 0xFF); innerB[1] = char((prim shr 8) and 0xFF)
        innerB[2] = char((prim shr 16) and 0xFF); innerB[3] = char((prim shr 24) and 0xFF)
        innerB[4..<innerB.len] = bwtData
        var msZ = newStringStream(innerB)
        var tmpOut = newStringStream("")
        tmpOut.write uint8(4 or (13 shl 4))
        discard catZEncodeCore(msZ, tmpOut, uint64(innerB.len), 4, 13, 8192, false, true, 256)
        tmpOut.setPosition(0)
        let zdata = tmpOut.readAll()
        let useMth = MethodCatZ
        if zdata.len + 24 < int(float(origF) * 0.95):
          outp.write kind
          outp.write uint8(relPath.len); outp.write relPath
          outp.write MethodLossy
          outp.wU64le(uint64(origF))
          let compPos = outp.getPosition(); outp.wU64le(0)
          let payStart = outp.getPosition()
          let extS = "bwt"
          outp.write uint8(extS.len); outp.write extS
          outp.write useMth
          outp.wU64le(uint64(innerB.len))
          let iph = outp.getPosition(); outp.wU64le(0)
          outp.write zdata
          let aft = outp.getPosition()
          let dataComp = uint64(aft - iph - 8)
          outp.setPosition(iph); outp.wU64le(dataComp)
          let compL = uint64(aft - payStart)
          outp.setPosition(compPos); outp.wU64le(compL); outp.setPosition(aft); entryCsumWrite(outp, 1, needSrcCrc())
          inc revCount
          let pct = 100.0 - float(compL) / float(origF) * 100.0
          echo "追加: ", dispName, " [REV-BWT(可逆)] ", origF, " → ", compL, " bytes (", pct.formatFloat(ffDecimal, 1), "%削減)"
          totOrig += uint64(origF)
          totComp += compL + uint64(22 + relPath.len)
          return

  # JSON用BWT: 512KB以下のみ
  if origF >= 1024 and origF <= 512 * 1024 and srcPath.toLowerAscii.endsWith(".json"):
    var fB: File
    if fB.open(srcPath, fmRead):
      var txt = newString(int(origF))
      let gotB = fB.readBuffer(addr txt[0], int(origF))
      fB.close()
      if gotB == int(origF):
        let (bwtData, prim) = bwtEncode(txt)
        var innerB = newString(4 + bwtData.len)
        innerB[0] = char(prim and 0xFF); innerB[1] = char((prim shr 8) and 0xFF)
        innerB[2] = char((prim shr 16) and 0xFF); innerB[3] = char((prim shr 24) and 0xFF)
        innerB[4..<innerB.len] = bwtData
        var msZ = newStringStream(innerB)
        var tmpOut = newStringStream("")
        tmpOut.write uint8(4 or (13 shl 4))
        discard catZEncodeCore(msZ, tmpOut, uint64(innerB.len), 4, 13, 8192, false, true, 256)
        tmpOut.setPosition(0)
        let zdata = tmpOut.readAll()
        let useMth = MethodCatZ
        if zdata.len + 24 < int(float(origF) * 0.95):
          outp.write kind
          outp.write uint8(relPath.len); outp.write relPath
          outp.write MethodLossy
          outp.wU64le(uint64(origF))
          let compPos = outp.getPosition(); outp.wU64le(0)
          let payStart = outp.getPosition()
          let extS = "bwt"
          outp.write uint8(extS.len); outp.write extS
          outp.write useMth
          outp.wU64le(uint64(innerB.len))
          let iph = outp.getPosition(); outp.wU64le(0)
          outp.write zdata
          let aft = outp.getPosition()
          let dataComp = uint64(aft - iph - 8)
          outp.setPosition(iph); outp.wU64le(dataComp)
          let compL = uint64(aft - payStart)
          outp.setPosition(compPos); outp.wU64le(compL); outp.setPosition(aft); entryCsumWrite(outp, 1, needSrcCrc())
          inc revCount
          let pct = 100.0 - float(compL) / float(origF) * 100.0
          echo "追加: ", dispName, " [REV-BWT(可逆)] ", origF, " → ", compL, " bytes (", pct.formatFloat(ffDecimal, 1), "%削減)"
          totOrig += uint64(origF)
          totComp += compL + uint64(22 + relPath.len)
          return

  # --- SQLite DB カラム分離圧縮(完全可逆・高圧縮) ---
  # レコードをパースしてカラム毎に分離し、各カラムを個別圧縮する。
  # 失敗時や効果薄時はフォールバック（後続のREV-DBへ）。
  if origF >= 1024 and origF <= 4 * 1024 * 1024:
    block tryDbColumnar:
      var fC = openFileStream(srcPath, fmRead)
      var header = newString(100)
      let gotH = fC.readData(addr header[0], 100)
      if gotH != 100 or header[0..15] != "SQLite format 3\x00":
        fC.close()
        break tryDbColumnar
      let pageSize = int(uint8(header[16])) * 256 + int(uint8(header[17]))
      if pageSize < 512 or pageSize > 65536:
        fC.close()
        break tryDbColumnar
      fC.setPosition(0)
      var dbData = newString(int(origF))
      let gotD = fC.readData(addr dbData[0], int(origF))
      fC.close()
      if gotD != int(origF):
        break tryDbColumnar
      let pageCount = (int(origF) + pageSize - 1) div pageSize
      var metaBuf = newStringStream("")
      var gapBuf = newStringStream("")
      var rowidBuf = newStringStream("")
      var rhdrBuf = newStringStream("")
      var colBufs = [newStringStream(""), newStringStream(""), newStringStream(""),
                     newStringStream(""), newStringStream("")]
      var maxCols = 0
      var totalRecs = 0
      var okParse = true
      for i in 0..<pageCount:
        let start = i * pageSize
        let endPos = min(start + pageSize, int(origF))
        if endPos - start < 8:
          okParse = false; break
        let base = if i == 0: 100 else: 0
        let pgLen = endPos - (start + base)
        if pgLen < 8:
          okParse = false; break
        let ptype = int(uint8(dbData[start+base]))
        if ptype != 5 and ptype != 13:
          okParse = false; break
        let hdrLen = if ptype == 5: 12 else: 8
        if pgLen < hdrLen:
          okParse = false; break
        let ncells = int(uint8(dbData[start+base+3])) * 256 + int(uint8(dbData[start+base+4]))
        let cs = int(uint8(dbData[start+base+5])) * 256 + int(uint8(dbData[start+base+6]))
        if cs < hdrLen + 2*ncells or cs > pgLen:
          okParse = false; break
        let prefixEnd = start + base + hdrLen + 2*ncells
        if prefixEnd > endPos:
          okParse = false; break
        if i == 0:
          metaBuf.write(dbData[start..<start+100])
          metaBuf.write(dbData[start+100..<prefixEnd])
        else:
          metaBuf.write(dbData[start..<prefixEnd])
        type CellInfo = tuple[cellOff: int, reclen: int, rowid: string, rhdr: string, cols: array[5, string], ncol: int]
        var cells: seq[CellInfo] = @[]
        var pageRaw = false
        if ptype != 13:
          pageRaw = true
        else:
          # check for overflow records first; if any, store whole content as gap
          for c in 0..<ncells:
            let cptr = int(uint8(dbData[start+base+hdrLen+2*c])) * 256 + int(uint8(dbData[start+base+hdrLen+2*c+1]))
            if cptr < cs or cptr >= pgLen:
              okParse = false; break
            let b = start + base + cptr
            let (psz, l1, ok1) = sqliteVarint(dbData, b, start+base+pgLen)
            if not ok1:
              okParse = false; break
            # record must fit fully in-page (no overflow support in columnar)
            if l1 + psz > pgLen - cptr:
              pageRaw = true
              break
          if not okParse: break
        if pageRaw:
          # store content area raw in gap stream; mark via meta flag
          metaBuf.write(char(1))
          if prefixEnd < endPos:
            gapBuf.write(dbData[prefixEnd..<endPos])
        else:
          metaBuf.write(char(0))
          for c in 0..<ncells:
            let cptr = int(uint8(dbData[start+base+hdrLen+2*c])) * 256 + int(uint8(dbData[start+base+hdrLen+2*c+1]))
            if cptr < cs or cptr >= pgLen:
              okParse = false; break
            let b = start + base + cptr
            let (psz, l1, ok1) = sqliteVarint(dbData, b, start+base+pgLen)
            if not ok1:
              okParse = false; break
            let (rid, l2, ok2) = sqliteVarint(dbData, b+l1, start+base+pgLen)
            if not ok2:
              okParse = false; break
            let (rhl, l3, ok3) = sqliteVarint(dbData, b+l1+l2, start+base+pgLen)
            if not ok3:
              okParse = false; break
            let p = b+l1+l2
            let e = p+rhl
            if e > start+base+pgLen or rhl < l3:
              okParse = false; break
            var colvals: array[5, string]
            var ncol = 0
            var q = p+l3
            var v = e
            var cok = true
            var dbgSerials = 0
            while q < e:
              let (st, l, okk) = sqliteVarint(dbData, q, start+base+pgLen)
              if not okk:
                cok = false; break
              let ln = sqliteSerLen(st)
              if ln < 0 or v+ln > start+base+pgLen:
                cok = false; break
              if ncol >= 5:
                cok = false; break
              colvals[ncol] = dbData[v..<v+ln]
              inc ncol
              v += ln; q += l
              inc dbgSerials
              if dbgSerials > 20:
                cok = false; break
            if not cok:
              okParse = false; break
            let reclen = v - b
            if b + reclen > start+base+pgLen:
              okParse = false; break
            cells.add((cptr, reclen, dbData[b..<b+l1+l2], dbData[p..<e], colvals, ncol))
            if ncol > maxCols: maxCols = ncol
          if not okParse: break
          for ce in cells:
            rowidBuf.write(ce.rowid)
            rhdrBuf.write(ce.rhdr)
            for j in 0..<ce.ncol:
              colBufs[j].write(ce.cols[j])
            inc totalRecs
          var intervals: seq[tuple[s, e: int]] = @[]
          for ce in cells:
            intervals.add((ce.cellOff, ce.cellOff + ce.reclen))
          intervals.sort(proc(a, b: tuple[s, e: int]): int = cmp(a.s, b.s))
          var gpos = cs
          for iv in intervals:
            if iv.s < gpos or iv.e > pgLen:
              okParse = false; break
            if iv.s > gpos:
              gapBuf.write(dbData[start+base+gpos..<start+base+iv.s])
            gpos = max(gpos, iv.e)
          if not okParse: break
          if gpos < pgLen:
            gapBuf.write(dbData[start+base+gpos..<start+base+pgLen])
      if not okParse or totalRecs == 0:
        break tryDbColumnar
      if maxCols > 5:
        break tryDbColumnar
      metaBuf.setPosition(0); rowidBuf.setPosition(0); rhdrBuf.setPosition(0); gapBuf.setPosition(0)
      let metaOrig = metaBuf.readAll(); rowidBuf.setPosition(0)
      let rowOrig = rowidBuf.readAll(); rhdrBuf.setPosition(0)
      let rhOrig = rhdrBuf.readAll(); gapBuf.setPosition(0)
      let gapOrig = gapBuf.readAll()
      var colOrigs: array[5, string]
      for j in 0..<5:
        colBufs[j].setPosition(0)
        colOrigs[j] = colBufs[j].readAll()
      proc compCatZ(data: string, pm, pb, ob: int): string =
        if data.len == 0: return ""
        var ms = newStringStream(data)
        var tmp = newStringStream("")
        tmp.write uint8(pm or (pb shl 4))
        discard catZEncodeCore(ms, tmp, uint64(data.len), pm, pb, ob, true, false, 256)
        tmp.setPosition(0)
        return tmp.readAll()
      proc compLz(data: string): string =
        if data.len == 0: return ""
        var ms = newStringStream(data)
        var tmp = newStringStream("")
        discard lzEncode(ms, tmp, uint64(data.len))
        tmp.setPosition(0)
        return tmp.readAll()
      let zMeta = compCatZ(metaOrig, 4, 15, 8192)
      let zRow = compCatZ(rowOrig, 4, 15, 8192)
      let zRh = compCatZ(rhOrig, 4, 15, 65536)
      var zCols: array[5, string]
      for j in 0..<5:
        if colOrigs[j].len == 0:
          zCols[j] = ""
        elif colOrigs[j].len < 4096:
          zCols[j] = compLz(colOrigs[j])
        else:
          zCols[j] = compCatZ(colOrigs[j], 4, 15, 262144)
      let zGap = compLz(gapOrig)
      # verify roundtrips before committing
      proc verifyCatZ(z: string, orig: string): bool =
        if orig.len == 0: return z.len == 0
        if z.len == 0: return false
        var ds = newStringStream(z)
        var oo = newStringStream("")
        try:
          catZDecode(ds, oo, uint64(orig.len))
        except CatchableError:
          return false
        oo.setPosition(0)
        return oo.readAll() == orig
      if not verifyCatZ(zMeta, metaOrig): break tryDbColumnar
      if not verifyCatZ(zRow, rowOrig): break tryDbColumnar
      if not verifyCatZ(zRh, rhOrig): break tryDbColumnar
      for j in 0..<5:
        if colOrigs[j].len == 0: continue
        if colOrigs[j].len < 4096:
          var ds = newStringStream(zCols[j]); var oo = newStringStream("")
          try: lzDecode(ds, oo, uint64(colOrigs[j].len))
          except CatchableError: break tryDbColumnar
          oo.setPosition(0)
          if oo.readAll() != colOrigs[j]: break tryDbColumnar
        else:
          if not verifyCatZ(zCols[j], colOrigs[j]): break tryDbColumnar
      block gapVerify:
        var ds = newStringStream(zGap); var oo = newStringStream("")
        try: lzDecode(ds, oo, uint64(gapOrig.len))
        except CatchableError: break tryDbColumnar
        oo.setPosition(0)
        if oo.readAll() != gapOrig: break tryDbColumnar
      var totalComp = zMeta.len + zRow.len + zRh.len + zGap.len + 200
      for j in 0..<5: totalComp += zCols[j].len
      if totalComp + 100 >= int(origF):
        break tryDbColumnar
      outp.write kind
      outp.write uint8(relPath.len); outp.write relPath
      outp.write MethodLossy
      outp.wU64le(uint64(origF))
      let compPos = outp.getPosition(); outp.wU64le(0)
      let payStart = outp.getPosition()
      let extS = "dbcol"
      outp.write uint8(extS.len); outp.write extS
      outp.write MethodCatZ
      outp.wU64le(uint64(totalComp))
      outp.wU64le(uint64(pageSize))
      outp.wU64le(uint64(pageCount))
      outp.wU64le(uint64(maxCols))
      outp.wU64le(uint64(totalRecs))
      proc writePart(mth: uint8, origLen: int, z: string) =
        outp.write mth
        outp.wU64le(uint64(origLen))
        outp.wU64le(uint64(z.len))
        outp.wU64le(uint64(origLen))
        outp.write z
      writePart(MethodCatZ, metaOrig.len, zMeta)
      writePart(MethodCatZ, rowOrig.len, zRow)
      writePart(MethodCatZ, rhOrig.len, zRh)
      for j in 0..<5:
        if colOrigs[j].len < 4096:
          writePart(MethodCatLz, colOrigs[j].len, zCols[j])
        else:
          writePart(MethodCatZ, colOrigs[j].len, zCols[j])
      writePart(MethodCatLz, gapOrig.len, zGap)
      let aft = outp.getPosition()
      let compL = uint64(aft - payStart)
      outp.setPosition(compPos); outp.wU64le(compL); outp.setPosition(aft); entryCsumWrite(outp, 1, needSrcCrc())
      inc revCount
      let pct = 100.0 - float(compL) / float(origF) * 100.0
      echo "追加: ", dispName, " [REV-DBCU(可逆)] ", origF, " → ", compL, " bytes (", pct.formatFloat(ffDecimal, 1), "%削減)"
      totOrig += uint64(origF)
      totComp += compL + uint64(22 + relPath.len)
      return

  # --- SQLite DB 構造可視化圧縮(完全可逆) ---
  if origF >= 1024 and origF <= 4 * 1024 * 1024:
    var fB2 = openFileStream(srcPath, fmRead)
    var header = newString(100)
    let gotH = fB2.readData(addr header[0], 100)
    if gotH == 100 and header[0..15] == "SQLite format 3\x00":
      let pageSize = int(uint8(header[16])) * 256 + int(uint8(header[17]))
      if pageSize >= 512 and pageSize <= 65536:
        fB2.setPosition(0)
        var dbData = newString(int(origF))
        let gotD = fB2.readData(addr dbData[0], int(origF))
        fB2.close()
        if gotD == int(origF):
            let pageCount = (origF + pageSize - 1) div pageSize
            var pageHeaders = newSeq[string](pageCount)
            var pagePayloads = newSeq[string](pageCount)
            for i in 0..<pageCount:
              let start = i * pageSize
              let endPos = min(start + pageSize, origF)
              let page = dbData[start..<endPos]
              if page.len >= 8:
                pageHeaders[i] = page[0..7]
                pagePayloads[i] = page[8..<page.len]
            var msH = newStringStream()
            for i in 0..<pageCount: msH.write(pageHeaders[i])
            msH.setPosition(0)
            var tmpOutH = newStringStream()
            tmpOutH.write uint8(4 or (15 shl 4))
            discard catZEncodeCore(msH, tmpOutH, uint64(msH.data.len), 4, 15, 8192, false, true, 64)
            tmpOutH.setPosition(0)
            let zdataH = tmpOutH.readAll()
            var msP = newStringStream()
            for i in 0..<pageCount: msP.write(pagePayloads[i])
            msP.setPosition(0)
            var tmpOutP = newStringStream()
            tmpOutP.write uint8(6 or (15 shl 4))
            # DBペイロード: 価格付きモードでOptBlock=8KB
            discard catZEncodeCore(msP, tmpOutP, uint64(msP.data.len), 6, 15, 8192, true, false, 256)
            tmpOutP.setPosition(0)
            let zdataP = tmpOutP.readAll()
            if zdataH.len + zdataP.len + 100 < int(origF):
              outp.write kind
              outp.write uint8(relPath.len); outp.write relPath
              outp.write MethodLossy
              outp.wU64le(uint64(origF))
              let compPos = outp.getPosition(); outp.wU64le(0)
              let payStart = outp.getPosition()
              let extS = "db"
              outp.write uint8(extS.len); outp.write extS
              # Write innerMth and transSize as expected by decompression
              outp.write MethodCatZ
              let transSize = uint64(msH.data.len) + uint64(zdataH.len) + uint64(msP.data.len) + uint64(zdataP.len) + 40
              outp.wU64le(transSize)
              # DB-specific format matching decompression exactly
              outp.wU64le(uint64(pageSize))
              outp.wU64le(uint64(pageCount))
              # Header
              outp.write MethodCatZ
              outp.wU64le(uint64(msH.data.len))  # headerSize
              outp.wU64le(uint64(zdataH.len))   # headerComp
              outp.wU64le(uint64(msH.data.len)) # extra u64 (discarded by decompression)
              outp.write zdataH
              # Payload
              outp.write MethodCatZ
              outp.wU64le(uint64(msP.data.len))
              outp.wU64le(uint64(zdataP.len))
              outp.wU64le(uint64(msP.data.len)) # extra u64 (discarded by decompression)
              outp.write zdataP
              let aft = outp.getPosition()
              let compL = uint64(aft - payStart)
              outp.setPosition(compPos); outp.wU64le(compL); outp.setPosition(aft); entryCsumWrite(outp, 1, needSrcCrc())
              inc revCount
              let pct = 100.0 - float(compL) / float(origF) * 100.0
              echo "追加: ", dispName, " [REV-DB(可逆)] ", origF, " → ", compL, " bytes (", pct.formatFloat(ffDecimal, 1), "%削減)"
              totOrig += uint64(origF)
              totComp += compL + uint64(22 + relPath.len)
              return

  # --- REV-NN(Tensor): --safe 時の指数/仮数分離 可逆変換(ZipNN 発想) ---

  # --- REV-NN(Tensor): --safe 時の指数/仮数分離 可逆変換(ZipNN 発想) ---
  if (not lossy) and origF >= 4096 and origF <= 512 * 1024 * 1024 and
     lossyCategory(srcPath) == "tensor":
    var emCont = ""
    if tensorEMSplit(srcPath, emCont):
      var msZ = newStringStream(emCont)
      var tmpOut = newStringStream("")
      let compData = catZEncode(msZ, tmpOut, uint64(emCont.len))
      tmpOut.setPosition(0)
      let zdata = tmpOut.readAll()
      outp.write kind
      outp.write uint8(relPath.len); outp.write relPath
      outp.write MethodLossy
      outp.wU64le(uint64(origF))
      let compPos = outp.getPosition(); outp.wU64le(0)
      let payStart = outp.getPosition()
      let extS = "emtens"
      outp.write uint8(extS.len); outp.write extS
      outp.write MethodCatZ
      outp.wU64le(uint64(emCont.len))
      let iph = outp.getPosition(); outp.wU64le(0)
      outp.write zdata
      let aft = outp.getPosition()
      let dataComp = uint64(aft - iph - 8)
      outp.setPosition(iph); outp.wU64le(dataComp)
      let compL = uint64(aft - payStart)
      outp.setPosition(compPos); outp.wU64le(compL); outp.setPosition(aft); entryCsumWrite(outp, 1, needSrcCrc())
      inc revCount
      let pct = 100.0 - float(compL) / float(origF) * 100.0
      echo "追加: ", dispName, " [REV-NNTENSOR] ",
           origF, " → ", compL, " bytes (", pct.formatFloat(ffDecimal, 1), "%削減・可逆)"
      totOrig += uint64(origF)
      totComp += compL + uint64(22 + relPath.len)
      return
  # --- テンソル量子化ファストパス (INT16/8/4 自動選択, ストリーミング・一時ファイル不要) ---
  # qbits=0(既定/auto)は FP16・INT8・INT4 を試算し、実出力サイズが最小のものを採用。
  # BF16 入力は fp16 でサイズ不変なので自動なら INT4(1/4) が選ばれる。
  # 不適(削減見込めず)の場合は 0 を返すので、そのまま下の可逆処理へフォールバック。
  if lossy and origF > 0 and lossyCategory(srcPath) == "tensor" and (qbits == 0 or qbits == 4 or qbits == 8 or qbits == 16):
    let (compL, chosenBits) = packTensorQuant(outp, kind, relPath, srcPath, uint64(origF), qbits)
    if compL > 0:
      inc lossyCount
      let pct = 100.0 - float(compL) / float(origF) * 100.0
      echo "追加: ", dispName, " [LOSSY-TENSOR qbits=", chosenBits,
           if qbits == 0: " auto" else: "", "] ",
           origF, " → ", compL, " bytes (", pct.formatFloat(ffDecimal, 1), "%削減)"
      totOrig += uint64(origF)
      totComp += compL + uint64(22 + relPath.len)
      return
    if compL > 0:
      inc lossyCount
      let pct = 100.0 - float(compL) / float(origF) * 100.0
      echo "追加: ", dispName, " [LOSSY-TENSOR qbits=", qbits, "] ",
           origF, " → ", compL, " bytes (", pct.formatFloat(ffDecimal, 1), "%削減)"
      totOrig += uint64(origF)
      totComp += compL + uint64(22 + relPath.len)
      return

  block lossySection:
    if lossy and origF > 0 and lossyCategory(srcPath) != "":
      let cat = lossyCategory(srcPath)
      echo "[", dispName, "] 変換試行 (", cat, " q=", q, ")..."
      let (tmp, extStr, label) = tryTranscode(srcPath, q)
      if tmp == "":
        echo "  変換ツールが無いか変換失敗。可逆で格納します"
      else:
        let transSize = getFileSize(tmp)
        if transSize >= origF:
          echo "  既に高圧縮のため非可逆変換に効果なし。可逆で格納します"
          removeFile(tmp)
        else:
          outp.write kind
          outp.write uint8(relPath.len)
          outp.write relPath
          outp.write MethodLossy
          outp.wU64le(uint64(origF))
          let compPos = outp.getPosition()
          outp.wU64le(0)
          let payStart = outp.getPosition()
          outp.write uint8(extStr.len)
          outp.write extStr
          var innerMth = pickReversible(tmp)
          outp.write innerMth
          outp.wU64le(uint64(transSize))
          var dataComp: uint64 = uint64(transSize)
          case innerMth
          of MethodVm:
            let iph = outp.getPosition()
            outp.wU64le(0)
            var tf = openFileStream(tmp, fmRead)
            dataComp = vmEncode(tf, outp, uint64(transSize))
            tf.close()
            let iaf = outp.getPosition()
            outp.setPosition(iph)
            outp.wU64le(dataComp)
            outp.setPosition(iaf)
          of MethodCatLz:
            let iph = outp.getPosition()
            outp.wU64le(0)
            var tf = openFileStream(tmp, fmRead)
            dataComp = lzEncode(tf, outp, uint64(transSize))
            tf.close()
            let iaf = outp.getPosition()
            outp.setPosition(iph)
            outp.wU64le(dataComp)
            outp.setPosition(iaf)
          else:
            var tf = openFileStream(tmp, fmRead)
            copyExact(tf, outp, dataComp)
            tf.close()
          let aft = outp.getPosition()
          let compL: uint64 = uint64(aft - payStart)
          outp.setPosition(compPos)
          outp.wU64le(compL)
          outp.setPosition(aft)
          entryCsumWrite(outp, 0, 0)
          removeFile(tmp)
          inc lossyCount
          let pct = 100.0 - float(compL) / float(origF) * 100.0
          echo "追加: ", dispName, " [LOSSY-", label,
               " q=", $q,
               "] ", origF, " → ", compL, " bytes (", pct.formatFloat(ffDecimal, 1), "%削減)"
          totOrig += uint64(origF)
          totComp += compL + uint64(22 + relPath.len)
          return

  var mth = MethodRaw
  if origF > 0:
    if isMp4(srcPath):
      mth = MethodMp4
    else:
      # フル実測比較: CAT-Z / CAT-LZ / CAT-VM の全てで圧縮し最小を採用
      var bestMth = MethodRaw
      var bestSize = int64(origF)

      block tryVm:
        var ft = openFileStream(srcPath, fmRead)
        var tOut = newStringStream("")
        discard vmEncode(ft, tOut, uint64(origF))
        let s = int64(tOut.getPosition())
        if s > 0 and s < bestSize:
          bestSize = s; bestMth = MethodVm
        ft.close()

      block tryLz:
        var ft = openFileStream(srcPath, fmRead)
        var tOut = newStringStream("")
        discard lzEncode(ft, tOut, uint64(origF))
        let s = int64(tOut.getPosition())
        if s > 0 and s < bestSize:
          bestSize = s; bestMth = MethodCatLz
        ft.close()

      block tryZ:
        var ft = openFileStream(srcPath, fmRead)
        var tOut = newStringStream("")
        discard catZEncode(ft, tOut, uint64(origF))
        let s = int64(tOut.getPosition())
        if s > 0 and s < bestSize:
          bestSize = s; bestMth = MethodCatZ
        ft.close()

# JSON専用: 大きなファイル向けにskeleton/keys/strs分離 + BWT + 個別圧縮
      if srcPath.toLowerAscii.endsWith(".json") and origF > 1024 * 1024:
        block tryJsonSplit:
          var skel, keys, strs: string
          if jsonSplit(srcPath, skel, keys, strs):
            # BWT変換はNUL無しのskeletonのみ（stringsはu32le長 prefixにNULを含むためBWT不可）
            let (skelBwtRaw, skelPrim) = bwtEncode(skel)
            var skelBwt = newString(4 + skelBwtRaw.len)
            skelBwt[0] = char(skelPrim and 0xFF); skelBwt[1] = char((skelPrim shr 8) and 0xFF)
            skelBwt[2] = char((skelPrim shr 16) and 0xFF); skelBwt[3] = char((skelPrim shr 24) and 0xFF)
            skelBwt[4..<skelBwt.len] = skelBwtRaw
            var msS = newStringStream(skelBwt)
            var msK = newStringStream(keys)
            var msT = newStringStream(strs)
            var tmpOutS = newStringStream("")
            var tmpOutK = newStringStream("")
            var tmpOutT = newStringStream("")
            # Skeleton(BWT済): adaptive CAT-Z
            discard catZEncode(msS, tmpOutS, uint64(skelBwt.len))
            # Keys: lzEncode (very fast, good for repetitive data)
            discard lzEncode(msK, tmpOutK, uint64(keys.len))
            # Strings(生): priced CAT-Z OptBlock=8K
            tmpOutT.write uint8(4 or (15 shl 4))
            discard catZEncodeCore(msT, tmpOutT, uint64(strs.len), 4, 15, 8192, true, false, 256)
            tmpOutS.setPosition(0); tmpOutK.setPosition(0); tmpOutT.setPosition(0)
            let zS = tmpOutS.readAll()
            let zK = tmpOutK.readAll()
            let zT = tmpOutT.readAll()
            let totalComp = zS.len + zK.len + zT.len + 20
            if totalComp < bestSize:
              bestSize = totalComp
              bestMth = MethodJson
              # Store compressed parts for later use (orig caches hold BWT lengths)
              skelJsonCache = zS
              keysJsonCache = zK
              strsJsonCache = zT
              skelOrigCache = uint64(skelBwt.len)
              keysOrigCache = uint64(keys.len)
              strsOrigCache = uint64(strs.len)

      mth = bestMth

  outp.write kind
  outp.write uint8(relPath.len)
  outp.write relPath
  outp.write mth
  outp.wU64le(uint64(origF))
  var comp: uint64 = uint64(origF)
  case mth
  of MethodRaw:
    outp.wU64le(comp)
    var f = openFileStream(srcPath, fmRead)
    copyExact(f, outp, comp)
    f.close()
    inc rawCount
  of MethodVm:
    let ph = outp.getPosition()
    outp.wU64le(0)
    var f = openFileStream(srcPath, fmRead)
    comp = vmEncode(f, outp, uint64(origF))
    f.close()
    let aft = outp.getPosition()
    outp.setPosition(ph)
    outp.wU64le(comp)
    outp.setPosition(aft)
    inc vmCount
  of MethodCatLz:
    let ph = outp.getPosition()
    outp.wU64le(0)
    var f = openFileStream(srcPath, fmRead)
    comp = lzEncode(f, outp, uint64(origF))
    f.close()
    let aft = outp.getPosition()
    outp.setPosition(ph)
    outp.wU64le(comp)
    outp.setPosition(aft)
    inc lzCount
  of MethodJson:
    let ph = outp.getPosition()
    outp.wU64le(0)
    # Write compressed skeleton, keys, strings + original skeleton length
    outp.wU64le(uint64(skelJsonCache.len))
    outp.wU64le(uint64(keysJsonCache.len))
    outp.wU64le(uint64(strsJsonCache.len))
    outp.wU64le(skelOrigCache)  # original skeleton length for catZDecode
    outp.wU64le(keysOrigCache)  # original keys length for lzDecode
    outp.wU64le(strsOrigCache)  # original strings length for lzDecode
    outp.write skelJsonCache
    outp.write keysJsonCache
    outp.write strsJsonCache
    let aft = outp.getPosition()
    comp = uint64(aft - ph - 8)
    outp.setPosition(ph)
    outp.wU64le(comp)
    outp.setPosition(aft)
    skelJsonCache = ""
    keysJsonCache = ""
    strsJsonCache = ""
    skelOrigCache = 0.uint64
    keysOrigCache = 0.uint64
    strsOrigCache = 0.uint64
    strsJsonCache = ""
    inc revCount
  of MethodCatZ:
    let ph = outp.getPosition()
    outp.wU64le(0)
    var f = openFileStream(srcPath, fmRead)
    if srcPath.toLowerAscii.endsWith(".json") and origF > 512 * 1024:
      # JSON用: 貪欲モードでOptBlock=32KB、pbits=15、pmove=3
      outp.write uint8(3 or (15 shl 4))  # ヘッダ: pmove=3, pbits=15
      comp = catZEncodeCore(f, outp, uint64(origF), 3, 15, 32768, false, true, 1024)
    else:
      comp = catZEncode(f, outp, uint64(origF))
    f.close()
    let aft = outp.getPosition()
    outp.setPosition(ph)
    outp.wU64le(comp)
    outp.setPosition(aft)
    inc zCount
  else:
    let ph = outp.getPosition()
    outp.wU64le(0)
    echo "[", dispName, "] MP4構造を解析..."
    comp = packMp4(srcPath, outp)
    let aft = outp.getPosition()
    outp.setPosition(ph)
    outp.wU64le(comp)
    outp.setPosition(aft)
    inc mp4Count
  entryCsumWrite(outp, 1, needSrcCrc())
  let pct = if origF > 0: 100.0 - float(comp) / float(origF) * 100.0 else: 0.0
  echo "追加: ", dispName, " [", methodName(mth), "] ",
       origF, " → ", comp, " bytes (", pct.formatFloat(ffDecimal, 1), "%削減)"
  totOrig += uint64(origF)
  totComp += comp + uint64(22 + relPath.len)

proc target0(outBase: string, kind: uint8, rel: string): string =
  if kind == KindSingle: outBase else: outBase / rel

proc unpackEntry(inp: Stream, outBase: string, kind: uint8, ver: int, baseP = "") =
  let plen = int(inp.rU8())
  var rel = newString(plen)
  if plen > 0 and inp.readData(addr rel[0], plen) != plen:
    fail("アーカイブが破損しています(パス)")
  let mth = uint8(inp.rU8())
  let orig = inp.rU64le()
  let comp = inp.rU64le()

  if mth == MethodLossy:
    let extLen = int(inp.rU8())
    var ext = newString(extLen)
    if extLen > 0 and inp.readData(addr ext[0], extLen) != extLen:
      fail("アーカイブが破損しています(ext)")
    let innerMth = uint8(inp.rU8())
    let transSize = inp.rU64le()
    let hdrLen = uint64(2 + extLen + 8)
    if comp < hdrLen: fail("アーカイブが破損しています(lossy)")
    let dataLen = comp - hdrLen
    if innerMth == MethodRaw:
      if dataLen != transSize:
        fail("アーカイブが破損しています(lossy RAW)")
    else:
      if dataLen < 8:
        fail("アーカイブが破損しています(lossy VM)")
    let sf = splitFile(target0(outBase, kind, rel))
    var finalTarget = sf.dir / (sf.name & "." & ext)
    if ext == "dtens":
      finalTarget = target0(outBase, kind, rel)   # 差分復元は指定名のまま出力
    let pdirL = parentDir(finalTarget)
    if pdirL.len > 0: createDir(pdirL)
    var f = openFileStream(finalTarget, fmWrite)
    if ext == "dtens":
      if baseP == "":
        f.close()
        fail("このアーカイブは差分(--base)形式です。復元には --base=<基準モデル> を指定してください")
      var msD = newStringStream()
      case innerMth
      of MethodRaw:
        copyExact(inp, msD, transSize)
      of MethodVm:
        discard inp.rU64le(); vmDecode(inp, msD, transSize)
      of MethodCatLz:
        discard inp.rU64le(); lzDecode(inp, msD, transSize)
      of MethodCatZ:
        discard inp.rU64le(); catZDecode(inp, msD, transSize)
      else:
        fail("アーカイブが破損しています(DELTA inner)")
      msD.setPosition(0)
      tensorDeltaApply(msD.readAll(), baseP, f)
      f.close()
      verifyEntryCsum(inp, ver, finalTarget)
      echo "復元成功: ", finalTarget, " [REV-DELTA(可逆・base適用)]"
      return
    elif ext == "db":
      let pageSize = int(inp.rU64le())
      let pageCount = int(inp.rU64le())
      # ヘッダデータを復元
      let headerMth = uint8(inp.rU8())
      let headerSize = inp.rU64le()
      let headerComp = inp.rU64le()
      var msH = newStringStream()
      case headerMth
      of MethodRaw:
        copyExact(inp, msH, headerComp)
      of MethodVm:
        discard inp.rU64le(); vmDecode(inp, msH, headerComp)
      of MethodCatLz:
        discard inp.rU64le(); lzDecode(inp, msH, headerComp)
      of MethodCatZ:
        discard inp.rU64le(); catZDecode(inp, msH, headerSize)
      else:
        fail("アーカイブが破損しています(db header inner)")
      msH.setPosition(0)
      var pageHeaders = newSeq[string](pageCount)
      for i in 0..<pageCount:
        var hdr = newString(8)
        if msH.readData(addr hdr[0], 8) != 8: fail("アーカイブが破損しています(db header)")
        pageHeaders[i] = hdr
      # ペイロードデータを復元
      let payloadMth = uint8(inp.rU8())
      let payloadSize = inp.rU64le()
      let payloadComp = inp.rU64le()
      var msP = newStringStream()
      case payloadMth
      of MethodRaw:
        copyExact(inp, msP, payloadComp)
      of MethodVm:
        discard inp.rU64le(); vmDecode(inp, msP, payloadComp)
      of MethodCatLz:
        discard inp.rU64le(); lzDecode(inp, msP, payloadComp)
      of MethodCatZ:
        discard inp.rU64le(); catZDecode(inp, msP, payloadSize)
      else:
        fail("アーカイブが破損しています(db payload inner)")
      msP.setPosition(0)
      var pagePayloads = newSeq[string](pageCount)
      for i in 0..<pageCount:
        let payloadLen = min(pageSize - 8, int(orig) - i * pageSize - 8)
        if payloadLen > 0:
          var payload = newString(payloadLen)
          if msP.readData(addr payload[0], payloadLen) != payloadLen: fail("アーカイブが破損しています(db payload)")
          pagePayloads[i] = payload
      # DBを再構築
      var dbData = newString(int(orig))
      for i in 0..<pageCount:
        let start = i * pageSize
        let endPos = min(start + pageSize, int(orig))
        if start < int(orig):
          dbData[start..<start+8] = pageHeaders[i]
          if pagePayloads[i].len > 0:
            dbData[start+8..<endPos] = pagePayloads[i]
      f.write(dbData)
      f.close()
      verifyEntryCsum(inp, ver, finalTarget)
      echo "復元成功: ", finalTarget, " [REV-DB(可逆)]"
      return
    elif ext == "dbcol":
      let pageSize = int(inp.rU64le())
      let pageCount = int(inp.rU64le())
      let maxCols = int(inp.rU64le())
      let totalRecs = int(inp.rU64le())
      if maxCols > 5 or pageCount <= 0 or pageCount > 100000: fail("アーカイブが破損しています(dbcol meta)")
      proc readPart(name: string): string =
        let m = uint8(inp.rU8())
        let osz = int(inp.rU64le())
        let csz = int(inp.rU64le())
        discard inp.rU64le()
        if osz < 0 or csz < 0 or osz > 512*1024*1024 or csz > 512*1024*1024: fail("アーカイブが破損しています(dbcol size)")
        var ms = newStringStream("")
        case m
        of MethodRaw:
          copyExact(inp, ms, uint64(csz))
        of MethodVm:
          vmDecode(inp, ms, uint64(osz))
        of MethodCatLz:
          lzDecode(inp, ms, uint64(osz))
        of MethodCatZ:
          var cbuf = newString(csz)
          if csz > 0 and inp.readData(addr cbuf[0], csz) != csz: fail("アーカイブが破損しています(dbcol read)")
          var ds = newStringStream(cbuf)
          catZDecode(ds, ms, uint64(osz))
        else:
          fail("アーカイブが破損しています(dbcol inner)")
        ms.setPosition(0)
        result = ms.readAll()
        if result.len != osz: fail("アーカイブが破損しています(dbcol サイズ)")
      let metaData = readPart("meta")
      let rowData = readPart("row")
      let rhData = readPart("rh")
      var colData: array[5, string]
      for j in 0..<5:
        colData[j] = readPart("col" & $j)
      let gapData = readPart("gap")
      var rowPos = 0
      var rhPos = 0
      var colPos = [0, 0, 0, 0, 0]
      var gapPos = 0
      var mpos = 0
      var dbData = newString(int(orig))
      var recIdx = 0
      for i in 0..<pageCount:
        let start = i * pageSize
        let endPos = min(start + pageSize, int(orig))
        let base = if i == 0: 100 else: 0
        let pgLen = endPos - (start + base)
        if pgLen < 8: fail("アーカイブが破損しています(dbcol page)")
        let ptype = if i == 0: int(uint8(metaData[mpos+100])) else: int(uint8(metaData[mpos]))
        let hl = if ptype == 5: 12 else: 8
        let ncells = if i == 0: int(uint8(metaData[mpos+100+3])) * 256 + int(uint8(metaData[mpos+100+4]))
                     else: int(uint8(metaData[mpos+3])) * 256 + int(uint8(metaData[mpos+4]))
        let pl = (if i == 0: 100 else: 0) + hl + 2*ncells
        if mpos + pl > metaData.len: fail("アーカイブが破損しています(dbcol meta)")
        dbData[start..<start+pl] = metaData[mpos..<mpos+pl]
        var pts: seq[int] = @[]
        let parr = mpos + (if i == 0: 100 else: 0) + hl
        for c in 0..<ncells:
          pts.add(int(uint8(metaData[parr+2*c])) * 256 + int(uint8(metaData[parr+2*c+1])))
        mpos += pl
        if mpos >= metaData.len: fail("アーカイブが破損しています(dbcol flag)")
        let isRaw = int(uint8(metaData[mpos])) != 0
        inc mpos
        type RecInfo = tuple[cellOff: int, data: string]
        var recs: seq[RecInfo] = @[]
        if ptype == 13 and not isRaw:
          for c in 0..<ncells:
            # row stream holds [payload-size varint][rowid varint] per record
            let (pszv, pszl, pok0) = sqliteVarint(rowData, rowPos, rowData.len)
            if not pok0: fail("アーカイブが破損しています(dbcol varint)")
            let (ridv, ridl, pok1) = sqliteVarint(rowData, rowPos+pszl, rowData.len)
            if not pok1: fail("アーカイブが破損しています(dbcol varint)")
            let (rhl, hl3, pok2) = sqliteVarint(rhData, rhPos, rhData.len)
            if not pok2: fail("アーカイブが破損しています(dbcol varint)")
            var q = rhPos + hl3
            var colLens: array[5, int]
            var ncol = 0
            while q < rhPos + rhl:
              let (st, ll, pok3) = sqliteVarint(rhData, q, rhData.len)
              if not pok3: fail("アーカイブが破損しています(dbcol varint)")
              let ln = sqliteSerLen(st)
              if ln < 0 or ncol >= 5: fail("アーカイブが破損しています(dbcol serial)")
              colLens[ncol] = ln
              inc ncol
              q += ll
            var rec = rowData[rowPos..<rowPos+pszl+ridl] & rhData[rhPos..<rhPos+rhl]
            for j in 0..<ncol:
              if colPos[j] + colLens[j] > colData[j].len: fail("アーカイブが破損しています(dbcol col)")
              rec.add(colData[j][colPos[j]..<colPos[j]+colLens[j]])
              colPos[j] += colLens[j]
            rowPos += pszl + ridl
            rhPos += rhl
            recs.add((pts[c], rec))
            inc recIdx
        # place records and fill gaps
        var intervals: seq[tuple[s, e: int]] = @[]
        for r in recs:
          intervals.add((r.cellOff, r.cellOff + r.data.len))
        intervals.sort(proc(a, b: tuple[s, e: int]): int = cmp(a.s, b.s))
        for r in recs:
          let absS = start + base + r.cellOff
          if absS + r.data.len > endPos:
            fail("アーカイブが破損しています(dbcol layout)")
          dbData[absS..<absS+r.data.len] = r.data
        let hl2 = if ptype == 5: 12 else: 8
        if recs.len == 0 and not isRaw:
          # empty leaf page: nothing to fill beyond prefix (cs should equal pgLen)
          discard
        elif isRaw:
          # raw page: content area stored verbatim in gap stream
          let contentStart = hl2 + 2*ncells
          let contentLen = pgLen - contentStart
          if contentLen > 0:
            if gapPos + contentLen > gapData.len: fail("アーカイブが破損しています(dbcol gap)")
            dbData[start+base+contentStart..<start+base+pgLen] = gapData[gapPos..<gapPos+contentLen]
            gapPos += contentLen
        else:
          let cs = int(uint8(dbData[start+base+5])) * 256 + int(uint8(dbData[start+base+6]))
          var g = cs
          for iv in intervals:
            if iv.s < g or iv.e > pgLen:
              fail("アーカイブが破損しています(dbcol layout)")
            if iv.s > g:
              let glen = iv.s - g
              if gapPos + glen > gapData.len: fail("アーカイブが破損しています(dbcol gap)")
              dbData[start+base+g..<start+base+iv.s] = gapData[gapPos..<gapPos+glen]
              gapPos += glen
            g = max(g, iv.e)
          if g < pgLen:
            let glen = pgLen - g
            if gapPos + glen > gapData.len: fail("アーカイブが破損しています(dbcol gap)")
            dbData[start+base+g..<endPos] = gapData[gapPos..<gapPos+glen]
            gapPos += glen
      if recIdx != totalRecs: fail("アーカイブが破損しています(dbcol count)")
      if gapPos != gapData.len: fail("アーカイブが破損しています(dbcol gap size)")
      if rowPos != rowData.len: fail("アーカイブが破損しています(dbcol row size)")
      if rhPos != rhData.len: fail("アーカイブが破損しています(dbcol rh size)")
      f.write(dbData)
      f.close()
      verifyEntryCsum(inp, ver, finalTarget)
      echo "復元成功: ", finalTarget, " [REV-DBCU(可逆)]"
      return
    elif ext == "json":
      var ms = newStringStream()
      case innerMth
      of MethodRaw:
        copyExact(inp, ms, transSize)
      of MethodVm:
        discard inp.rU64le(); vmDecode(inp, ms, transSize)
      of MethodCatLz:
        discard inp.rU64le(); lzDecode(inp, ms, transSize)
      of MethodCatZ:
        discard inp.rU64le(); catZDecode(inp, ms, transSize)
      else:
        fail("アーカイブが破損しています(JSON inner)")
      ms.setPosition(0)
      let slen = int(ms.rU64le()); let klen = int(ms.rU64le()); let tlen = int(ms.rU64le())
      if slen < 0 or klen < 0 or tlen < 0 or slen+klen+tlen > 1024*1024*1024:
        fail("アーカイブが破損しています(JSONコンテナ)")
      var skelC = newString(slen)
      var keysC = newString(klen)
      var strsC = newString(tlen)
      if slen > 0: discard ms.readData(addr skelC[0], slen)
      if klen > 0: discard ms.readData(addr keysC[0], klen)
      if tlen > 0: discard ms.readData(addr strsC[0], tlen)
      jsonReassemble(skelC, keysC, strsC, int64(orig), f)
      f.close()
      verifyEntryCsum(inp, ver, finalTarget)
      echo "復元成功: ", finalTarget, " [REV-JSON(可逆)]"
      return
    elif ext == "bwt":
      var msB = newStringStream()
      case innerMth
      of MethodRaw:
        copyExact(inp, msB, transSize)
      of MethodVm:
        discard inp.rU64le(); vmDecode(inp, msB, transSize)
      of MethodCatLz:
        discard inp.rU64le(); lzDecode(inp, msB, transSize)
      of MethodCatZ:
        discard inp.rU64le(); catZDecode(inp, msB, transSize)
      else:
        fail("アーカイブが破損しています(BWT inner)")
      msB.setPosition(0)
      var primBytes = newString(4)
      if msB.readData(addr primBytes[0], 4) != 4: fail("アーカイブが破損しています(BWT prim)")
      let prim = int(uint8(primBytes[0])) or (int(uint8(primBytes[1])) shl 8) or (int(uint8(primBytes[2])) shl 16) or (int(uint8(primBytes[3])) shl 24)
      let bwtData = msB.readAll()
      let decoded = bwtDecode(bwtData, prim)
      if decoded.len != int(orig): fail("アーカイブが破損しています(BWT サイズ)")
      f.write(decoded)
      f.close()
      verifyEntryCsum(inp, ver, finalTarget)
      echo "復元成功: ", finalTarget, " [REV-BWT(可逆)]"
      return
    elif ext == "safetensors":
      case innerMth
      of MethodRaw:
        restoreTensorPayload(inp, f, transSize)
      of MethodVm:
        discard inp.rU64le()
        var ms = newStringStream()
        vmDecode(inp, ms, transSize)
        ms.setPosition(0)
        restoreTensorPayload(ms, f, transSize)
      of MethodCatLz:
        discard inp.rU64le()
        var ms = newStringStream()
        lzDecode(inp, ms, transSize)
        ms.setPosition(0)
        restoreTensorPayload(ms, f, transSize)
      of MethodCatZ:
        discard inp.rU64le()
        var ms = newStringStream()
        catZDecode(inp, ms, transSize)
        ms.setPosition(0)
        restoreTensorPayload(ms, f, transSize)
      else:
        fail("アーカイブが破損しています(tensor inner)")
    else:
      case innerMth
      of MethodRaw:
        copyExact(inp, f, dataLen)
      of MethodVm:
        discard inp.rU64le()
        vmDecode(inp, f, transSize)
      of MethodCatLz:
        discard inp.rU64le()
        lzDecode(inp, f, transSize)
      of MethodCatZ:
        discard inp.rU64le()
        catZDecode(inp, f, transSize)
      else:
        fail("アーカイブが破損しています(lossy method)")
    f.close()
    verifyEntryCsum(inp, ver, finalTarget)
    if ext == "db":
      echo "復元成功: ", finalTarget, " [REPACK(可逆)]"
      echo "  ※ SQLite VACUUM 等の再圧縮は可逆です。元のファイルと同一です"
    else:
      echo "復元成功: ", finalTarget, " [LOSSY]"
      echo "  ※ 非可逆モードで保存されたファイルです(元のデータとは一致しません)"
    return

  let target = target0(outBase, kind, rel)
  let pdir = parentDir(target)
  if pdir.len > 0: createDir(pdir)
  var f = openFileStream(target, fmWrite)
  case mth
  of MethodRaw:
    copyExact(inp, f, comp)
  of MethodVm:
    vmDecode(inp, f, orig)
  of MethodCatLz:
    lzDecode(inp, f, orig)
  of MethodCatZ:
    catZDecode(inp, f, orig)
  of MethodJson:
    # Read compressed skeleton, keys, strings + original skeleton length
    let skelComp = inp.rU64le()
    let keysComp = inp.rU64le()
    let strsComp = inp.rU64le()
    let skelOrig = inp.rU64le()
    let keysOrig = inp.rU64le()
    let strsOrig = inp.rU64le()
    var skelData = newString(skelComp.int)
    var keysData = newString(keysComp.int)
    var strsData = newString(strsComp.int)
    if inp.readData(addr skelData[0], skelComp.int) != skelComp.int: fail("アーカイブが破損しています(JSON skel)")
    if inp.readData(addr keysData[0], keysComp.int) != keysComp.int: fail("アーカイブが破損しています(JSON keys)")
    if inp.readData(addr strsData[0], strsComp.int) != strsComp.int: fail("アーカイブが破損しています(JSON strs)")
    # Skeleton was compressed with catZEncodeCore (has header byte), use catZDecode
    var msS = newStringStream(skelData)
    var msK = newStringStream(keysData)
    var msT = newStringStream(strsData)
    var skelOut = newStringStream("")
    var keysOut = newStringStream("")
    var strsOut = newStringStream("")
    catZDecode(msS, skelOut, skelOrig)
    lzDecode(msK, keysOut, keysOrig)
    catZDecode(msT, strsOut, strsOrig)
    # BWT逆変換 (skeleton のみBWT済み、stringsは生)
    skelOut.setPosition(0); strsOut.setPosition(0)
    let skelBwt = skelOut.readAll(); let strs = strsOut.readAll()
    if skelBwt.len < 4: fail("アーカイブが破損しています(JSON BWT)")
    let skelPrim = int(uint8(skelBwt[0])) or (int(uint8(skelBwt[1])) shl 8) or (int(uint8(skelBwt[2])) shl 16) or (int(uint8(skelBwt[3])) shl 24)
    let skel = bwtDecode(skelBwt[4..^1], skelPrim)
    jsonReassemble(skel, keysOut.data, strs, orig.int64, f)
  else:
    unpackMp4(inp, f, comp)
  f.close()
  verifyEntryCsum(inp, ver, target)
  echo "復元成功: ", target, " [", methodName(mth), "]"

proc collectFiles(dir, root: string, list: var seq[tuple[rel, abs: string]]) =
  for kindEl, path in walkDir(dir):
    if kindEl == pcDir:
      collectFiles(path, root, list)
    elif kindEl == pcFile:
      list.add((relativePath(path, root), path))

proc runPack(input, output: string, lossy = true, q = 51, qbits = 0, baseMode = false, safeAi = false, basePackP = "") =
  let outputFile = if splitFile(output).ext == ".catcmp": output else: output & ".catcmp"
  if not (fileExists(input) or dirExists(input)):
    fail("入力が存在しません: " & input)
  # 例外: catcomp アーカイブを c の入力にできない(二重圧縮の禁止)
  if fileExists(input):
    if splitFile(input).ext == ".catcmp":
      fail(".catcmp ファイルは圧縮(c)の入力にできません: " & input & "\n" &
           "       復元する場合は d を使用してください")
    # 拡張子を変更していてもマジックで検出する
    var f = openFileStream(input, fmRead)
    var magic = newString(8)
    if f.readData(addr magic[0], 8) == 8 and magic == CatMagic:
      f.close()
      fail("入力は CatelliteCompressor のアーカイブです(圧縮(c)の入力にできません): " &
           input & "\n" &
           "       復元する場合は d を使用してください")
    f.close()
  var modeStr = if baseMode: " [モデルモード(--base)]" elif safeAi: " [セーフAIモード]" elif lossy: " [スマートモード]" else: " [セーフモード]"
  echo "[*] CatelliteCompressor v", FormatVersion, ": パック中", modeStr, "..."
  # --base: 明示指定 --base=PATH を優先、未指定なら従来通り自動検出
  var baseP = basePackP
  if baseMode and baseP == "":
    if dirExists(input):
      var blist: seq[tuple[rel, abs: string]] = @[]
      collectFiles(input, input, blist)
      blist.sort(proc(x, y: tuple[rel, abs: string]): int = cmp(x.rel, y.rel))
      for bf in blist:
        let bext = toLowerAscii(splitFile(bf.abs).ext)
        if bext in tensorExts:
          baseP = bf.abs
          echo "[*] 基準モデル: ", extractFilename(baseP)
          break
    else:
      let bext = toLowerAscii(splitFile(input).ext)
      if bext in tensorExts:
        baseP = input
        echo "[*] 基準モデル: ", extractFilename(baseP)
  if baseP != "":
    echo "[*] 基準モデル: ", extractFilename(baseP)
  var fs = openFileStream(outputFile, fmWrite)
  fs.write CatMagic
  fs.write FormatVersion
  var rawCount = 0
  var vmCount = 0
  var lzCount = 0
  var revCount = 0
  var zCount = 0
  var mp4Count = 0
  var lossyCount = 0
  # JSON分割圧縮用キャッシュ
  var skelJsonCache = ""
  var keysJsonCache = ""
  var strsJsonCache = ""
  var skelOrigCache = 0.uint64
  var keysOrigCache = 0.uint64
  var strsOrigCache = 0.uint64
  var totOrig: uint64 = 9
  var totComp: uint64 = 10
  if dirExists(input):
    var list: seq[tuple[rel, abs: string]] = @[]
    collectFiles(input, input, list)
    list.sort(proc(x, y: tuple[rel, abs: string]): int = cmp(x.rel, y.rel))
    if list.len == 0:
      fail("ディレクトリが空です: " & input)
    for it in list:
      packEntry(fs, KindMember, it.rel, it.abs, it.rel,
                rawCount, vmCount, mp4Count, lossyCount, lzCount, zCount, revCount, totOrig, totComp,
                lossy, q, qbits, baseP, safeAi, skelJsonCache, keysJsonCache, strsJsonCache, skelOrigCache, keysOrigCache, strsOrigCache)
  else:
    packEntry(fs, KindSingle, "", input, extractFilename(input),
              rawCount, vmCount, mp4Count, lossyCount, lzCount, zCount, revCount, totOrig, totComp,
              lossy, q, qbits, baseP, safeAi, skelJsonCache, keysJsonCache, strsJsonCache, skelOrigCache, keysOrigCache, strsOrigCache)
  fs.write KindEnd
  fs.close()
  let pct = 100.0 - float(totComp) / float(totOrig) * 100.0
  echo "[+] 圧縮完了: ", outputFile
  echo " 合計: ", totOrig, " → ", totComp, " bytes (", pct.formatFloat(ffDecimal, 2), "%削減)"
  echo " 内訳: CAT-LZ:", lzCount, " CAT-VM:", vmCount, " RAW:", rawCount, " MP4:", mp4Count,
       " LOSSY:", lossyCount, " CAT-Z:", zCount, " REV-JSON:", revCount
  if lossyCount > 0:
    echo " ※ 非可逆エントリを含みます。復元結果は元のファイルと同一にはなりません"
  if totOrig > 0 and float(totComp) / float(totOrig) > 0.95:
    echo " ※ 入力の大半は既に圧縮済み/無秩序データのため、可逆ではこれ以上の縮小は原理的に困難です"

proc runUnpack(input, output: string, baseP = "") =
  var inputFile = input
  if not fileExists(inputFile) and fileExists(inputFile & ".catcmp"):
    inputFile &= ".catcmp"
  var fs = openFileStream(inputFile, fmRead)
  var magic = newString(8)
  if fs.readData(addr magic[0], 8) != 8:
    fail("ファイルが短すぎます: " & inputFile)
  if magic != CatMagic:
    fail("CatelliteCompressorのフォーマット(.catcmp)ではありません。")
  let ver = int(fs.readUint8())
  if ver < 1 or ver > 2:
    fail("未対応のフォーマットバージョンです: " & $ver)
  echo "[*] CatelliteCompressor v", ver, ": 展開中"
  var nEntries = 0
  while true:
    let kind = uint8(fs.rU8())
    if kind == KindEnd:
      if nEntries == 0:
        fail("アーカイブが破損しています(エントリが見つかりません)")
      break
    if kind != KindSingle and kind != KindMember:
      fail("アーカイブが破損しています(kind)")
    unpackEntry(fs, output, kind, ver, baseP)
    inc nEntries
  fs.close()
  echo "[+] 復元完了: ", output

when isMainModule:
  var rest: seq[string] = @[]
  var lossy = true
  var safeAi = false
  var q = 51
  var qbits = 0
  var baseMode = false
  var baseDecP = ""   # d 時の --base=PATH (復元用基準モデル)
  var basePackP = ""  # c 時の --base=PATH (圧縮用基準モデル)
  var expectBasePack = false  # 次の引数が --base のパス
  for a in commandLineParams():
    if a == "--safe":
      lossy = false
      safeAi = false
    elif a == "--safe=ai":
      lossy = true
      safeAi = true
    elif a == "--lossy":
      lossy = true
      safeAi = false
    elif a.startswith("--lossy="):
      lossy = true
      safeAi = false
      try:
        q = parseInt(a[8..^1])
      except CatchableError:
        discard
      if q < 0 or q > 51:
        quit("エラー: 品質 q は0〜51で指定してください")
    elif a == "--qbits":
      qbits = 0
    elif a.startswith("--base="):
      baseMode = true
      basePackP = a[7..^1]
      baseDecP = a[7..^1]
    elif a == "--base":
      baseMode = true
      expectBasePack = true
    elif expectBasePack:
      basePackP = a
      baseDecP = a
      expectBasePack = false
    elif a.startswith("--qbits="):
      let v = a[8..^1]
      if v == "auto":
        qbits = 0
      else:
        try:
          qbits = parseInt(v)
        except CatchableError:
          qbits = -1
        if qbits notin [4, 8, 16]:
          quit("エラー: --qbits は auto / 4 / 8 / 16 で指定してください(既定 auto)")
    else:
      rest.add a
  if rest.len >= 2 and rest[0] == "ztest":
    proc dbgPrintTags() =
      const names = ["other","rep","len","lenx","nbtree","extras","literal"]
      for i in 0..<8:
        if dbgTagBytes[i] > 0:
          stderr.writeLine("BYTES ", names[i], "=", dbgTagBytes[i])
    var fi = openFileStream(rest[1], fmRead)
    var fo = openFileStream("/tmp/z.bin", fmWrite)
    let n = catZEncode(fi, fo, uint64(getFileSize(rest[1])))
    fi.close(); fo.close()
    dbgPrintTags()
    echo "encoded: ", n
    var fi2 = openFileStream("/tmp/z.bin", fmRead)
    var fo2 = openFileStream("/tmp/z.out", fmWrite)
    catZDecode(fi2, fo2, uint64(getFileSize(rest[1])))
    fi2.close(); fo2.close()
    quit(0)
  if rest.len >= 2 and rest[0] == "skewtest":
    var fo = openFileStream("/tmp/rc.bin", fmWrite)
    var e = rcInitE(fo)
    var p = Prob(1 shl (ProbBits - 1))
    for _ in 0..<200_000:
      e.rcEncBit(p, 0)
    e.rcFlush()
    fo.close()
    echo "skew encoded: ", getFileSize("/tmp/rc.bin"), " bytes"
    var fi2 = openFileStream("/tmp/rc.bin", fmRead)
    var d = rcInitD(fi2)
    p = Prob(1 shl (ProbBits - 1))
    var bad = 0
    for _ in 0..<200_000:
      if d.rcDecBit(p) != 0: inc bad
    fi2.close()
    echo "decode mismatches: ", bad
    quit(0)
  if rest.len >= 2 and rest[0] == "lztest":
    var fi = openFileStream(rest[1], fmRead)
    var fo = openFileStream("/tmp/lz.bin", fmWrite)
    let n = lzEncode(fi, fo, uint64(getFileSize(rest[1])))
    fi.close(); fo.close()
    echo "encoded: ", n
    var fi2 = openFileStream("/tmp/lz.bin", fmRead)
    var fo2 = openFileStream("/tmp/lz.out", fmWrite)
    lzDecode(fi2, fo2, uint64(getFileSize(rest[1])))
    fi2.close(); fo2.close()
    quit(0)

  if rest.len >= 8 and rest[0] == "ztune":
    let path = rest[1]
    let pm = parseInt(rest[2]); let pb = parseInt(rest[3]); let ob = parseInt(rest[4])
    let priced = parseInt(rest[5]) != 0; let greedy = parseInt(rest[6]) != 0; let mc = parseInt(rest[7])
    let origSize = uint64(getFileSize(path))
    var fi = openFileStream(path, fmRead)
    var fo = newStringStream("")
    fo.write uint8(pm or (pb shl 4))
    discard catZEncodeCore(fi, fo, origSize, pm, pb, ob, priced, greedy, mc)
    fi.close()
    fo.setPosition(0)
    let z = fo.readAll()
    var ds = newStringStream(z)
    var outp = newStringStream("")
    try:
      catZDecode(ds, outp, origSize)
    except CatchableError as e:
      echo "FAIL decode: ", e.msg
      quit(2)
    outp.setPosition(0)
    let o = outp.readAll()
    var f = openFileStream(path, fmRead)
    var orig = newString(int(origSize))
    discard f.readData(addr orig[0], int(origSize))
    f.close()
    echo "comp=", z.len, " ok=", (o == orig)
    quit(if o == orig: 0 else: 3)

  if rest.len < 2 or (rest[0] == "c" and rest.len < 3 and basePackP == ""):
    stdout.write Usage
    quit(1)
  var outPath = ""
  case rest[0]
  of "c":
    if rest.len >= 3:
      outPath = rest[2]
    else:
      outPath = rest[1] & ".catcmp"
    try:
      runPack(rest[1], outPath, lossy, q, qbits, baseMode, safeAi, basePackP)
    except CatchableError as e:
      quit("エラー: " & e.msg)
  of "d":
    if rest.len < 3:
      stdout.write Usage
      quit(1)
    try:
      runUnpack(rest[1], rest[2], baseDecP)
    except CatchableError as e:
      quit("エラー: " & e.msg)
  else:
    stdout.write Usage
    quit(1)
