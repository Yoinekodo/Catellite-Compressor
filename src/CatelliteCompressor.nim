import std/[os, strutils, streams, algorithm]

const MagicV2 = "CATCOMP2"
const FormatVersion = 2'u8
const WindowSize = 65535
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

const OpLit = 1'u8
const OpLitLong = 2'u8
const OpRle = 3'u8
const OpMatch = 4'u8
const OpRepeat = 5'u8

const Usage = "==================================\n" &
  " CatelliteCompressor v2 (.catcomp / CAT-VM)\n" &
  "==================================\n" &
  "使い方:\n" &
  " 圧縮: ./CatelliteCompressor c [オプション] <入力(ファイル/Dir)> <出力>\n" &
  " 復元: ./CatelliteCompressor d <入力> <出力(ファイル/Dir)>\n" &
  "オプション:\n" &
  " --lossy[=CRF]  動画を非可逆再符号化して格納(既定CRF=51, 0=高品質〜51=最小)\n" &
  "                ※ 復元結果は元のファイルと同一にはなりません\n" &
  " ※ .catcomp 拡張子は省略可能 / 可逆モードは完全可逆 / ストリーミング処理"

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
        buf.delete(0, cut - 1)
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
    if hist.len >= 4 * WindowSize:
      hist.delete(0, 2 * WindowSize - 1)
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

proc preferVm(path: string, offset: int64 = 0, avail: int64 = -1): bool =
  let a = if avail < 0: int64(getFileSize(path)) else: avail
  if a <= 0: return false
  sampleVmRatio(path, offset, a) < RawThreshold

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
    if bx.payloadLen > 0 and preferVm(srcPath, bx.payloadOff, bx.payloadLen):
      mth = MethodVm
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
    else:
      fail("アーカイブが破損しています(box method)")
    consumed += comp
  if consumed != expectedComp: fail("アーカイブが破損しています(box合計)")

proc methodName(m: uint8): string =
  case m
  of MethodRaw: "RAW"
  of MethodVm: "CAT-VM"
  of MethodMp4: "MP4"
  else: "MP4-LOSSY"

const videoExts = [".mp4", ".m4v", ".mov", ".mkv", ".webm", ".avi", ".ts",
                   ".mts", ".m2ts", ".flv", ".wmv", ".mpg", ".mpeg"]

proc isVideoCandidate(path: string): bool =
  if toLowerAscii(splitFile(path).ext) in videoExts:
    return true
  isMp4(path)

proc tryTranscode(srcPath: string, crf: int): string =
  if findExe("ffmpeg") == "": return ""
  let tmp = getTempDir() & "/catcc_" & $getCurrentProcessId() & ".mp4"
  if fileExists(tmp): removeFile(tmp)
  let cmd = "ffmpeg -y -v error -i \"" & srcPath & "\"" &
            " -map 0:v:0 -map \"0:a:0?\"" &
            " -c:v libx264 -crf " & $crf & " -preset veryfast -pix_fmt yuv420p" &
            " -c:a aac -b:a 48k -movflags +faststart \"" & tmp & "\" > /dev/null 2>&1"
  let code = execShellCmd(cmd)
  if code == 0 and fileExists(tmp) and getFileSize(tmp) > 0:
    return tmp
  if fileExists(tmp): removeFile(tmp)
  return ""

proc packEntry(outp: Stream, kind: uint8, relPath, srcPath, dispName: string,
               rawCount: var int, vmCount: var int, mp4Count: var int,
               lossyCount: var int, totOrig: var uint64, totComp: var uint64,
               lossy: bool, crf: int) =
  if relPath.len > 255: fail("パスが長すぎます(255byte以内): " & relPath)
  let origF = getFileSize(srcPath)

  block lossySection:
    if lossy and origF > 0 and isVideoCandidate(srcPath):
      echo "[", dispName, "] 非可逆トランスコード試行 (CRF=", crf, ")..."
      let tmp = tryTranscode(srcPath, crf)
      if tmp.len == 0:
        echo "  ffmpegが利用できないか変換失敗。可逆で格納します"
      else:
        let transSize = getFileSize(tmp)
        if transSize >= origF:
          echo "  既に高圧縮のため非可逆変換に効果なし。可逆で格納します"
          removeFile(tmp)
        else:
          let extStr0 = toLowerAscii(splitFile(srcPath).ext)
          let extStr = if extStr0.len > 1: extStr0[1..^1] else: "mp4"
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
          var innerMth = MethodRaw
          if preferVm(tmp): innerMth = MethodVm
          outp.write innerMth
          outp.wU64le(uint64(transSize))
          var dataComp: uint64 = uint64(transSize)
          if innerMth == MethodVm:
            let iph = outp.getPosition()
            outp.wU64le(0)
            var tf = openFileStream(tmp, fmRead)
            dataComp = vmEncode(tf, outp, uint64(transSize))
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
          echo "追加: ", dispName, " [MP4-LOSSY CRF=", crf, "] ",
               origF, " → ", compL, " bytes (", pct.formatFloat(ffDecimal, 1), "%削減, 非可逆)"
          totOrig += uint64(origF)
          totComp += compL + uint64(22 + relPath.len)
          return

  var mth = MethodRaw
  if origF > 0:
    if isMp4(srcPath):
      mth = MethodMp4
    elif preferVm(srcPath):
      mth = MethodVm
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
    if innerMth == MethodRaw and dataLen != transSize:
      fail("アーカイブが破損しています(lossy RAW)")
    let sf = splitFile(target0(outBase, kind, rel))
    let finalTarget = if extLen > 0: sf.dir / (sf.name & "." & ext) else: target0(outBase, kind, rel)
    let pdirL = parentDir(finalTarget)
    if pdirL.len > 0: createDir(pdirL)
    var f = openFileStream(finalTarget, fmWrite)
    case innerMth
    of MethodRaw:
      copyExact(inp, f, dataLen)
    else:
      vmDecode(inp, f, transSize)
    f.close()
    echo "復元成功: ", finalTarget, " [MP4-LOSSY]"
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

proc runPack(input, output: string, lossy = false, crf = 51) =
  let outputFile = if splitFile(output).ext == ".catcomp": output else: output & ".catcomp"
  if not (fileExists(input) or dirExists(input)):
    fail("入力が存在しません: " & input)
  echo "[*] CatelliteCompressor v2 (CAT-VM): パック中", if lossy: " [非可逆モード]" else: "", "..."
  var fs = openFileStream(outputFile, fmWrite)
  fs.write MagicV2
  fs.write FormatVersion
  var rawCount = 0
  var vmCount = 0
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
                rawCount, vmCount, mp4Count, lossyCount, totOrig, totComp,
                lossy, crf)
  else:
    packEntry(fs, KindSingle, "", input, extractFilename(input),
              rawCount, vmCount, mp4Count, lossyCount, totOrig, totComp,
              lossy, crf)
  fs.write KindEnd
  fs.close()
  let pct = 100.0 - float(totComp) / float(totOrig) * 100.0
  echo "[+] 圧縮完了: ", outputFile
  echo " 合計: ", totOrig, " → ", totComp, " bytes (", pct.formatFloat(ffDecimal, 2), "%削減)"
  echo " 内訳: CAT-VM:", vmCount, " RAW:", rawCount, " MP4:", mp4Count, " LOSSY:", lossyCount
  if lossyCount > 0:
    echo " ※ 非可逆エントリを含みます。復元結果は元のファイルと同一にはなりません"
  if totOrig > 0 and float(totComp) / float(totOrig) > 0.95:
    echo " ※ 入力の大半は既に圧縮済み/無秩序データのため、可逆ではこれ以上の縮小は原理的に困難です"

proc runUnpack(input, output: string) =
  var inputFile = input
  if not fileExists(inputFile) and fileExists(inputFile & ".catcomp"):
    inputFile &= ".catcomp"
  var fs = openFileStream(inputFile, fmRead)
  var magic = newString(8)
  if fs.readData(addr magic[0], 8) != 8:
    fail("ファイルが短すぎます: " & inputFile)
  if magic != MagicV2:
    if magic == "CATCOMP1":
      fail("旧形式(v1)は非対応です。再度 v2 で圧縮してください。")
    fail("CatelliteCompressorのフォーマット(.catcomp)ではありません。")
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
  var lossy = false
  var crf = 51
  for a in commandLineParams():
    if a == "--lossy":
      lossy = true
    elif a.startsWith("--lossy="):
      lossy = true
      try:
        crf = parseInt(a[8..^1])
      except CatchableError:
        discard
      if crf < 0 or crf > 51:
        quit("エラー: CRFは0〜51で指定してください")
    else:
      rest.add a
  if rest.len < 3:
    stdout.write Usage
    quit(1)
  case rest[0]
  of "c":
    try:
      runPack(rest[1], rest[2], lossy, crf)
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
