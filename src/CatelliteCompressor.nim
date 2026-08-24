import std/[os, strutils, streams, algorithm, json, math]

const CatMagic = "CATCOMP1"
const FormatVersion = 1'u8
const WindowSize = 65535
const LzWindow = 4 * 1024 * 1024   # CAT-LZ v2: 最大参照距離(4MB)
const MinMatch = 4
const MaxMatchLen = 255
const ChunkSize = 1 shl 20
const SampleSize = 1 shl 18
const RawThreshold = 0.97
const HashBits = 18
const HashSize = 1 shl HashBits

const KindEnd = 0'u8
const KindSingle = 1'u8
const KindMember = 2'u8

const MethodRaw = 0'u8
const MethodVm = 1'u8
const MethodMp4 = 2'u8
const MethodLossy = 3'u8
const MethodCatLz = 4'u8

# 一時ファイル置き場(小さな /tmp(tmpfs) を避け、実ディスク上を利用)
proc ccTmpDir(): string =
  result = getEnv("CATCOMP_TMP")
  if result == "": result = "/root/.catcc_tmp"
  try: createDir(result)
  except: result = "."

const OpLit = 1'u8
const OpLitLong = 2'u8
const OpRle = 3'u8
const OpMatch = 4'u8
const OpRepeat = 5'u8

const Usage = "==================================\n" &
  " CatelliteCompressor v2 (.catcmp / CAT-VM + CAT-LZ)\n" &
  "==================================\n" &
  "使い方:\n" &
  " 圧縮: ./CatelliteCompressor c [オプション] <入力(ファイル/Dir)> <出力>\n" &
  " 復元: ./CatelliteCompressor d <入力> <出力(ファイル/Dir)>\n" &
  "オプション:\n" &
  " (既定)         スマートモード+自動最適化:\n" &
  "                ・テンソルは FP16/INT8/INT4 を試算し最小サイズを自動採用\n" &
  "                ・可逆データは CAT-LZ / CAT-VM の小さい方を自動採用\n" &
  " --safe         何も削除しない完全可逆モード。\n" &
  "                復元結果が常に元のバイト列と完全一致\n" &
  " --lossy[=q]    スマートモードを明示(q=0高品質〜51最小, 既定51)\n" &
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
  wU32le(s, v and 0xFFFFFFFF'u64)
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

proc hashAt(buf: string, i: int): uint32 =
  let x = uint32(uint8(buf[i])) or
          (uint32(uint8(buf[i+1])) shl 8) or
          (uint32(uint8(buf[i+2])) shl 16) or
          (uint32(uint8(buf[i+3])) shl 24)
  (x * 2654435761'u32) shr (32 - HashBits)

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
      flags = flags or uint8(1'u8 shl nflags)
    pend.add payload
    inc nflags
    if nflags == 8: flushGroup()

  proc emitMatch(off, l: int) =
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
      tok.add char(255'u8)
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
                if tokBits < litBits:
                  emitMatch(off, l)
                let insEnd = min(l, 4096)
                for k in 1..<insEnd:
                  if k mod 4 == 0:
                    if idx + k + MinMatch <= limit:
                      head[hashAt(buf, idx + k)] = int64(base + idx + k)
                inc(idx, l)
                handled = true
                break tryMatch
      if not handled:
        addItem(false, $buf[idx])
        inc idx
    if eof and idx >= buf.len: break
  flushGroup()
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
      if (flags and (1'u8 shl bit)) == 0:
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
proc pickReversible(path: string, offset: int64 = 0, avail: int64 = -1): uint8 =
  let a = if avail < 0: int64(getFileSize(path)) else: avail
  if a <= 0: return MethodRaw
  let rv = sampleVmRatio(path, offset, a)
  let rl = sampleLzRatio(path, offset, a)
  let best = min(rv, rl)
  if best >= RawThreshold: return MethodRaw
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
      if orig + 8 > 0xFFFFFFFF'u64: fail("MP4再構築エラー: サイズ超過")
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
  let sign = (i shr 16) and 0x8000'u32
  let mant = (i shr 12) and 0x7FF'u32
  let exp = (i shr 23) and 0xFF'u32
  if exp == 0xFF'u32:
    if mant != 0: return 0x7E00'u16
    return uint16(sign or 0x7C00'u32)
  var e = int(exp) - 127 + 15
  var m = (i shr 13) and 0x3FF'u32
  if e <= 0:
    if e < -10: return uint16(sign)
    m = (m or 0x400'u32) shr uint32(1 - e)
    return uint16(sign or m)
  if e == 0x1F: return uint16(sign or 0x7C00'u32)
  if (m and 0x1000'u32) != 0: inc e
  return uint16(sign or (uint32(e) shl 10) or (m and 0x3FF'u32))

proc rd32(b: seq[byte], o: int): uint32 =
  uint32(b[o]) or (uint32(b[o+1]) shl 8) or
  (uint32(b[o+2]) shl 16) or (uint32(b[o+3]) shl 24)
proc rd64(b: seq[byte], o: int): uint64 =
  uint64(rd32(b, o)) or (uint64(rd32(b, o+4)) shl 32)
proc f16tof32(b: seq[byte], o: int): float32 =
  let h = uint32(b[o]) or (uint32(b[o+1]) shl 8)
  let sign = (h shr 15) and 1'u32
  let exp = (h shr 10) and 0x1F'u32
  let mant = h and 0x3FF'u32
  var f: uint32
  if exp == 0:
    if mant == 0: f = sign shl 31
    else:
      var e = 127 - 15
      var m = mant
      while (m and 0x400'u32) == 0: m = m shl 1; dec e
      m = m and 0x3FF'u32
      f = (sign shl 31) or (uint32(e) shl 23) or (m shl 13)
  elif exp == 0x1F:
    f = (sign shl 31) or 0x7F800000'u32 or (mant shl 13)
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
  uint16((i shr 16) and 0xFFFF'u32)

proc elemF32(chunk: seq[byte], so: int, dtype: string): float32 =
  case dtype
  of "F32": cast[float32](rd32(chunk, so))
  of "F64": float32(cast[float64](rd64(chunk, so)))
  of "F16": f16tof32(chunk, so)
  of "BF16": bf16tof32(chunk, so)
  else: 0'f32

proc tensorMaxAbs(srcPath: string, bufStart, tstart, tend: int, dtype: string): float32 =
  var f = openFileStream(srcPath, fmRead)
  f.setPosition(bufStart + tstart)
  let total = tend - tstart
  let eb = elemBytes(dtype)
  var remaining = total
  var chunk = newSeq[byte](1 shl 22)
  var mx = 0'f32
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

# ---- テンソル量子化ヘルパ(候補試算はヘッダ組立のみで完結・データ再読込なし) ----
type QuantInfo = tuple[name: string, dtype: string, start: int, en: int, numel: int, shape: seq[int]]

proc quantMaxAbsAll(srcPath: string, infos: seq[QuantInfo], bufStart: int): seq[float32] =
  result = newSeq[float32](infos.len)
  for i, t in infos:
    if t.dtype in ["F32", "F64", "F16", "BF16"]:
      result[i] = tensorMaxAbs(srcPath, bufStart, t.start, t.en, t.dtype)

proc quantRenderScales(infos: seq[QuantInfo], maxAbs: seq[float32], bits: int): JsonNode =
  result = newJObject()
  let rng = if bits == 4: 7.0'f32 else: 127.0'f32
  for i, t in infos:
    if t.dtype in ["F32", "F64", "F16", "BF16"]:
      let mx = maxAbs[i]
      let sc = if mx <= 0'f32: 1.0'f32 else: mx / rng
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
    for k in 0'u64..<8'u64:
      outp.write uint8(uint64((u shr (k * 8'u64)) and 0xFF))
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
  var f = openFileStream(srcPath, fmRead)
  if f.atEnd(): f.close(); return (0'u64, 0)
  let hlen = int(f.rU64le())
  if hlen <= 0 or hlen > 500_000_000: f.close(); return (0'u64, 0)
  var hdrBytes = newString(hlen)
  if f.readData(addr hdrBytes[0], hlen) != hlen: f.close(); return (0'u64, 0)
  var hdr: JsonNode
  try: hdr = parseJson(hdrBytes)
  except: f.close(); return (0'u64, 0)
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
    f.close(); return (0'u64, 0)
  # エントリ全体を直接書き出し
  let ext = "safetensors"
  let produced = bestProd
  let compL = uint64(1 + ext.len + 1 + 8 + produced)
  outp.write kind
  outp.write uint8(relPath.len)
  outp.write relPath
  outp.write MethodLossy
  outp.wU64le(origF)
  outp.wU64le(compL)
  outp.write uint8(ext.len)
  outp.write ext
  outp.write MethodRaw
  outp.wU64le(uint64(produced))
  outp.wU64le(uint64(bestNhs.len))
  outp.write bestNhs
  # pass2: 実データをストリーミング量子化して書き出し
  const CH = 1 shl 22
  var chunk = newSeq[byte](CH)
  let rngC = if bestBits == 4: 7.0'f32 else: 127.0'f32
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
        if f.readData(addr chunk[0], take) != take: f.close(); return (0'u64, 0)
        outp.write(cast[string](chunk[0..<take]))
        remaining -= take
    elif bestBits == 8:
      let mx = maxAbs[i]
      let sc = if mx <= 0'f32: 1.0'f32 else: mx / rngC
      while remaining > 0:
        let take = min(remaining, CH)
        if f.readData(addr chunk[0], take) != take: f.close(); return (0'u64, 0)
        let ne = take div eb
        for j in 0..<ne:
          let v = elemF32(chunk, j * eb, t.dtype)
          var qq = int(round(float(v) / float(sc)))
          if qq > 127: qq = 127
          if qq < -127: qq = -127
          outp.write uint8(if qq < 0: qq + 256 else: qq)
        remaining -= take
    elif bestBits == 4:
      let mx = maxAbs[i]
      let sc = if mx <= 0'f32: 1.0'f32 else: mx / rngC
      while remaining > 0:
        let take = min(remaining, CH)
        if f.readData(addr chunk[0], take) != take: f.close(); return (0'u64, 0)
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
            outp.write uint8((uint8(q0 and 0xF)) or (uint8(q1 and 0xF) shl 4))
          else:
            outp.write uint8(uint8(q0 and 0xF))
        remaining -= take
    else:
      while remaining > 0:
        let take = min(remaining, CH)
        if f.readData(addr chunk[0], take) != take: f.close(); return (0'u64, 0)
        let ne = take div eb
        for j in 0..<ne:
          let v = elemF32(chunk, j * eb, t.dtype)
          let hh = f32tof16(v)
          outp.write uint8(hh and 0xFF)
          outp.write uint8((hh shr 8) and 0xFF)
        remaining -= take
  f.close()
  result = (compL, bestBits)

# 展開時: 量子化された safetensors ペイロードを読み、
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
      let sc = if scales.hasKey(t.name): float32(float(scales[t.name].getFloat(1.0))) else: 1.0'f32
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
      let sc = if scales.hasKey(t.name): float32(float(scales[t.name].getFloat(1.0))) else: 1.0'f32
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
               lossyCount: var int, lzCount: var int, totOrig: var uint64, totComp: var uint64,
                lossy: bool, q: int, qbits: int) =
  if relPath.len > 255: fail("パスが長すぎます(255byte以内): " & relPath)
  let origF = getFileSize(srcPath)

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
      mth = pickReversible(srcPath)
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
  let pct = if origF > 0: 100.0 - float(comp) / float(origF) * 100.0 else: 0.0
  echo "追加: ", dispName, " [", methodName(mth), "] ",
       origF, " → ", comp, " bytes (", pct.formatFloat(ffDecimal, 1), "%削減)"
  totOrig += uint64(origF)
  totComp += comp + uint64(22 + relPath.len)

proc target0(outBase: string, kind: uint8, rel: string): string =
  if kind == KindSingle: outBase else: outBase / rel

proc unpackEntry(inp: Stream, outBase: string, kind: uint8) =
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
    let finalTarget = sf.dir / (sf.name & "." & ext)
    let pdirL = parentDir(finalTarget)
    if pdirL.len > 0: createDir(pdirL)
    var f = openFileStream(finalTarget, fmWrite)
    if ext == "safetensors":
      restoreTensorPayload(inp, f, transSize)
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
      else:
        fail("アーカイブが破損しています(lossy method)")
    f.close()
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
  else:
    unpackMp4(inp, f, comp)
  f.close()
  echo "復元成功: ", target, " [", methodName(mth), "]"

proc collectFiles(dir, root: string, list: var seq[tuple[rel, abs: string]]) =
  for kindEl, path in walkDir(dir):
    if kindEl == pcDir:
      collectFiles(path, root, list)
    elif kindEl == pcFile:
      list.add((relativePath(path, root), path))

proc runPack(input, output: string, lossy = true, q = 51, qbits = 0) =
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
  echo "[*] CatelliteCompressor v2 (CAT-VM/CAT-LZ): パック中",
       if lossy: " [スマートモード(非可逆変換含む)]" else: " [セーフモード(完全可逆)]", "..."
  var fs = openFileStream(outputFile, fmWrite)
  fs.write CatMagic
  fs.write FormatVersion
  var rawCount = 0
  var vmCount = 0
  var lzCount = 0
  var mp4Count = 0
  var lossyCount = 0
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
                rawCount, vmCount, mp4Count, lossyCount, lzCount, totOrig, totComp,
                lossy, q, qbits)
  else:
    packEntry(fs, KindSingle, "", input, extractFilename(input),
              rawCount, vmCount, mp4Count, lossyCount, lzCount, totOrig, totComp,
              lossy, q, qbits)
  fs.write KindEnd
  fs.close()
  let pct = 100.0 - float(totComp) / float(totOrig) * 100.0
  echo "[+] 圧縮完了: ", outputFile
  echo " 合計: ", totOrig, " → ", totComp, " bytes (", pct.formatFloat(ffDecimal, 2), "%削減)"
  echo " 内訳: CAT-LZ:", lzCount, " CAT-VM:", vmCount, " RAW:", rawCount, " MP4:", mp4Count,
       " LOSSY:", lossyCount
  if lossyCount > 0:
    echo " ※ 非可逆エントリを含みます。復元結果は元のファイルと同一にはなりません"
  if totOrig > 0 and float(totComp) / float(totOrig) > 0.95:
    echo " ※ 入力の大半は既に圧縮済み/無秩序データのため、可逆ではこれ以上の縮小は原理的に困難です"

proc runUnpack(input, output: string) =
  var inputFile = input
  if not fileExists(inputFile) and fileExists(inputFile & ".catcmp"):
    inputFile &= ".catcmp"
  var fs = openFileStream(inputFile, fmRead)
  var magic = newString(8)
  if fs.readData(addr magic[0], 8) != 8:
    fail("ファイルが短すぎます: " & inputFile)
  if magic != CatMagic:
    fail("CatelliteCompressorのフォーマット(.catcmp)ではありません。")
  discard fs.readUint8()
  echo "[*] CatelliteCompressor v2: 展開中..."
  while true:
    let kind = uint8(fs.rU8())
    if kind == KindEnd: break
    if kind != KindSingle and kind != KindMember:
      fail("アーカイブが破損しています(kind)")
    unpackEntry(fs, output, kind)
  fs.close()
  echo "[+] 復元完了: ", output

when isMainModule:
  var rest: seq[string] = @[]
  var lossy = true
  var q = 51
  var qbits = 0  # 0 = auto: 実出力が最小になるビット数を自動選択
  for a in commandLineParams():
    if a == "--safe":
      # 何も削除しない完全可逆モード(変換を一切行わない)
      lossy = false
    elif a == "--lossy":
      lossy = true
    elif a.startsWith("--lossy="):
      lossy = true
      try:
        q = parseInt(a[8..^1])
      except CatchableError:
        discard
      if q < 0 or q > 51:
        quit("エラー: 品質 q は0〜51で指定してください")
    elif a == "--qbits":
      qbits = 0
    elif a.startsWith("--qbits="):
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
if rest.len >= 2 and rest[0] == "lztest":
  block:
    # 開発用: lzEncode -> lzDecode 単体ラウンドトリップ検証
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
  if rest.len < 3:
    stdout.write Usage
    quit(1)
  case rest[0]
  of "c":
    try:
      runPack(rest[1], rest[2], lossy, q, qbits)
    except CatchableError as e:
      quit("エラー: " & e.msg)
  of "d":
    try:
      runUnpack(rest[1], rest[2])
    except CatchableError as e:
      quit("エラー: " & e.msg)
  else:
    stdout.write Usage
    quit(1)
