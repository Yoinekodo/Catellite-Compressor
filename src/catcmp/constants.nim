const
  CatMagic* = "CATCOMP1"
  FormatVersion* = 1.uint8
  WindowSize* = 65535
  LzWindow* = 65535
  MinMatch* = 4
  LazyThresh* = 2
  MaxMatchLen* = 255
  ChunkSize* = 1 shl 20
  SampleSize* = 1 shl 18
  RawThreshold* = 0.97
  HashBits* = 18
  HashSize* = 1 shl HashBits
  HashBits2* = 15
  HashSize2* = 1 shl HashBits2

  KindEnd* = 0.uint8
  KindSingle* = 1.uint8
  KindMember* = 2.uint8

  MethodRaw* = 0.uint8
  MethodVm* = 1.uint8
  MethodMp4* = 2.uint8
  MethodLossy* = 3.uint8
  MethodCatLz* = 4.uint8
  MethodJson* = 5.uint8
  MethodCatZ* = 6.uint8

  OpLit* = 1.uint8
  OpLitLong* = 2.uint8
  OpRle* = 3.uint8
  OpMatch* = 4.uint8
  OpRepeat* = 5.uint8

  EmMagic* = 0x315F4D45.uint32

  ProbBits* = 15
  ZPosBits* = 2
  ZPosStates* = 1 shl ZPosBits
  ZSlots* = 16
  ZLitCtx* = 128
  MinMatchZ* = 4
  ZMaxNb* = 24
  ZKeepBytes* = 4 * 1024 * 1024
  ZMaxOff* = 16 * 1024 * 1024
  MaxChain* = 512
  OptBlock* = 8192

type
  Prob* = uint16

const
  videoExts* = [".mp4", ".m4v", ".mov", ".mkv", ".webm", ".avi", ".ts",
                ".mts", ".m2ts", ".flv", ".wmv", ".mpg", ".mpeg"]
  audioExts* = [".wav", ".flac", ".aac", ".m4a", ".mp3", ".ogg", ".opus",
                ".wma", ".alac", ".ape", ".mid", ".midi"]
  imageExts* = [".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".gif",
                ".webp", ".ico", ".tga", ".ppm", ".pbm"]
  tensorExts* = [".safetensors", ".safetensor", ".bin"]
  modelExts* = [".obj", ".gltf", ".glb", ".stl", ".fbx", ".blend",
                ".ply", ".3ds", ".dae", ".wrl", ".x3d", ".usdz", ".usda"]

  Usage* = "==================================\n" &
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