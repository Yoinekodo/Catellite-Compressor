import std/[algorithm, sequtils]
import ../constants

proc bwtEncode*(s: string): tuple[bwt: string, primary: int] =
  let n0 = s.len
  if n0 == 0: return ("", 0)
  var t = s & "\x00"
  let n = t.len
  var suf = newSeq[int](n)
  for i in 0..<n: suf[i] = i
  var rank = newSeq[int](n)
  var tmp = newSeq[int](n)
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

proc bwtDecode*(bwt: string, primary: int): string =
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
  if tmp.len > 0 and tmp[^1] == '\x00':
    result = tmp[0..^2]
  else:
    result = tmp