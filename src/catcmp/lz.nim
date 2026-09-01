import std/[algorithm]
import ../constants, ../io

var dbgLitLz* = 0
var dbgMthLz* = 0
var dbgMlenLz* = 0

proc lzEncode*(src, dst: Stream, inputLimit: uint64): uint64 =
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
      flags = flags or uint8(1.uint8 shl nflags)
    pend.add payload
    inc nflags
    if nflags == 8: flushGroup()

  proc emitMatch(off, l: int) =
    inc dbgMthLz; dbgMlenLz += l
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
      if not handled:
        addItem(false, $buf[idx])
        inc dbgLitLz
        inc idx
    if eof and idx >= buf.len: break
  flushGroup()
  when defined CATCC_LZDBG:
    stderr.writeLine("lzdbg lit=", dbgLitLz, " mth=", dbgMthLz, " mlen=", dbgMlenLz,
                     " cov=", dbgLitLz+dbgMlenLz, " idx=", idx, " buflen=", buf.len, " eof=", eof)
  result = written

proc lzDecode*(src, dst: Stream, origSize: uint64) =
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