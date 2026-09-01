import std/[algorithm]
import ../constants, ../io

var dbgLitVm* = 0
var dbgMthVm* = 0
var dbgMlenVm* = 0

proc hashAt*(buf: string, i: int): uint32 =
  let x = uint32(uint8(buf[i])) or
          (uint32(uint8(buf[i+1])) shl 8) or
          (uint32(uint8(buf[i+2])) shl 16) or
          (uint32(uint8(buf[i+3])) shl 24)
  (x * 2654435761.uint32) shr (32 - HashBits)

proc vmEncode*(src, dst: Stream, inputLimit: uint64): uint64 =
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
  when defined CATCC_LZDBG:
    stderr.writeLine("vmdbg lit=", dbgLitVm, " mth=", dbgMthVm, " mlen=", dbgMlenVm,
                     " cov=", dbgLitVm+dbgMlenVm, " idx=", idx, " buflen=", buf.len, " eof=", eof)
  result = written

proc vmDecode*(src, dst: Stream, origSize: uint64) =
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
        fail("アーカイブが破損しています")
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