import std/[os, streams, strutils]

proc ccTmpDir*(): string =
  result = getEnv("CATCOMP_TMP")
  if result == "": result = "/root/.catcc_tmp"
  try: createDir(result)
  except: result = "."

proc fail*(msg: string) =
  raise newException(IOError, msg)

proc wU16le*(s: Stream, v: uint64) =
  s.write uint8(v and 0xFF)
  s.write uint8((v shr 8) and 0xFF)

proc wU32le*(s: Stream, v: uint64) =
  s.write uint8(v and 0xFF)
  s.write uint8((v shr 8) and 0xFF)
  s.write uint8((v shr 16) and 0xFF)
  s.write uint8((v shr 24) and 0xFF)

proc wU64le*(s: Stream, v: uint64) =
  wU32le(s, v and 0xFFFFFFFF.uint64)
  wU32le(s, v shr 32)

proc wU32be*(s: Stream, v: uint64) =
  s.write uint8((v shr 24) and 0xFF)
  s.write uint8((v shr 16) and 0xFF)
  s.write uint8((v shr 8) and 0xFF)
  s.write uint8(v and 0xFF)

proc wU64be*(s: Stream, v: uint64) =
  for k in countdown(56, 0):
    s.write uint8((v shr k) and 0xFF)

proc rU8*(s: Stream): uint64 = uint64(s.readUint8())

proc rU16le*(s: Stream): uint64 =
  rU8(s) or (rU8(s) shl 8)

proc rU32le*(s: Stream): uint64 =
  rU8(s) or (rU8(s) shl 8) or (rU8(s) shl 16) or (rU8(s) shl 24)

proc rU64le*(s: Stream): uint64 =
  rU32le(s) or (rU32le(s) shl 32)

proc copyExact*(src, dst: Stream, n: uint64) =
  var tmp = newString(ChunkSize)
  var left = n
  while left > 0:
    let want = int(min(left, uint64(tmp.len)))
    let got = src.readData(addr tmp[0], want)
    if got <= 0: fail("アーカイブが破損しています(RAW)")
    dst.writeData(addr tmp[0], got)
    left -= uint64(got)