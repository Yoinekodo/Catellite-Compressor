import os, strutils

proc createTestData() =
  let baseDir = "test_dir"
  createDir(baseDir)
  
  writeFile(baseDir / "sample.txt", repeat("CatelliteCompressorのテストデータ。繰り返しによる圧縮を検証します。\n", 500))
  
  var binData = newString(10000)
  for i in 0..<10000:
    binData[i] = chr(i mod 256)
  writeFile(baseDir / "data.bin", binData)
  
  createDir(baseDir / "subdir")
  writeFile(baseDir / "subdir/info.text", "階層構造のテストです。これもcatcompでパックされます。")
  
  echo "テスト用ディレクトリ 'test_dir' を作成しました。"
  
createTestData()