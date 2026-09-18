# CatelliteCompressor

**v0.6.0**

次世代パラダイム圧縮ツール。ファイル / ディレクトリを `.catcmp` アーカイブに
まとめ、内蔵の3つの可逆コーデック **CAT-VM** / **CAT-LZ** / **CAT-Z** と
テンソル量子化で圧縮します。外部コマンド非依存(動画/画像/音声変換の ffmpeg は任意)。

**CAT-Z** は LZMA2 の事象木 + レンジコーディングを Nim でゼロから実装した
汎用可逆コーデックです。AI モデルの INT4 量子化と組み合わせることで、
LLM の重み(BF16 等)を **最大 75% 削減**します。

```
使い方:
  圧縮: ./CatelliteCompressor c [オプション] <入力(ファイル/Dir)> <出力>
  復元: ./CatelliteCompressor d [--base=<基準モデル>] <入力> <出力>

  オプション:
   (既定)         ハイブリッドモード: 拡張子に応じた最適圧縮を自動選択
                  .safetensors/.pt/.bin → AIモデル圧縮(INT4量子化等)
                  それ以外 → CAT-Z(LZMA2最適化圧縮)
   --safe         完全可逆モード(全ファイル)
   --safe=ai      AIモデルのみ可逆(通常ファイルは通常圧縮)
   --lossy[=q]    スマートモードを明示(q=0高品質〜51最小, 既定51)
   --base         モデル-aware圧縮(デルタ圧縮): 最初のsafetensorsを基準に
   --qbits=[auto|16|8|4]
                  テンソル量子化ビット(既定 auto=最小サイズ自動選択)
                  4 = INT4(1/4, 最小) / 8 = INT8(1/2) / 16 = FP16(高品質)
  ```
`.catcmp` 拡張子は省略可能です。省略時は自動で付与します。

※ `.catcmp` アーカイブを `c` の入力に渡すとエラーになります(二重圧縮の禁止)。
  復元は `d` を使用してください。

---

## 特徴

- **CAT-Z — LZMA2 風汎用コーデック** — バイナリツリー一致検索・事象木符号化・
  レンジコーディングを内蔵。pb/pm を自動グリッドサーチで最適化。
  AI モデル以外の全ファイル形式で汎用圧縮として使用されます。
- **完全可逆 3 コーデック** — CAT-Z(汎用) / CAT-VM(命令ストリーム化) /
  CAT-LZ(高密度 LZ)のうち最適な方を自動選択。復元後は元のバイト列と
  **完全一致**します。
- **テンソル自動量子化** — safetensors の重みを FP16/INT8/INT4 で試算し、
  **実出力が最小になるビット数を自動採用**(既定)。復元時は**入力と同じ dtype**
  (F32→F32, BF16→BF16, F16→F16, F64→F64)へ逆量子化するため、そのまま推論に使えます。
- **動画構造保管 (MP4 ハンドラ)** — MP4 を box 単位で解析し、box ごとに
  RAW / CAT-VM / CAT-LZ を選択して保持。動画品質は劣化しません。
- **外部依存の最小化** — 7z・sqlite3 は廃止。アーカイブ/DB は内蔵コーデックの
  完全可逆格納です(ffmpeg は動画/画像/音声変換のみに任意で使用)。
- **ストリーミング処理** — チャンク分割で数 GB の入力も安全に処理。テンソル量子化は
  一時ファイルを作らずアーカイブへ直接書き出すため、空き容量が少ない環境でも動作します。
- **誠実な圧縮率報告** — 膨張する入力(ランダムデータ等)は RAW のまま通過させ、
  「不可能を無理にねじ曲げる」ことはしません。

---

## インストール

必要条件: Nim 2.x (動作確認済み: 2.2.10)。外部ライブラリ依存なし。
比較ベンチマーク用に xz / zstd / 7z / gzip があると `run.py` が動作します。

```bash
# nimble 経由
nimble build -d:release

# または直接(依存パッケージなし)
nim c -d:release --opt:speed -o:CatelliteCompressor src/CatelliteCompressor.nim
```

ビルド成果物(`CatelliteCompressor`、`nimcache/`、`*.catcmp`、`*.out` 等)は
`.gitignore` 済みのためコミットされません。

---

## 使用例

```bash
# モデルを圧縮 (既定=自動最適化: INT4/INT8/FP16 の最小を自動選択)
./CatelliteCompressor c model.safetensors model_small
./CatelliteCompressor d model_small.catcmp model_restored.safetensors
# → 入力と同じ dtype (例: BF16) で復元される

# ビット数を手動指定
./CatelliteCompressor c --qbits=8  model.safetensors m8    # INT8 (1/2)
./CatelliteCompressor c --qbits=4  model.safetensors m4    # INT4 (1/4, 最小)
./CatelliteCompressor c --qbits=16 model.safetensors m16   # FP16 (高品質)

# ディレクトリを圧縮
./CatelliteCompressor c ./my_project ./archive
./CatelliteCompressor d ./archive.catcmp ./restored

# 動画をスマートモードで大幅圧縮(要 ffmpeg)
./CatelliteCompressor c movie.mp4 small
./CatelliteCompressor c --lossy=40 movie.mp4 small40     # q=40 高品質寄り

# 何も削除しない完全可逆
./CatelliteCompressor c --safe movie.mp4 safe
./CatelliteCompressor d safe.catcmp movie_restored.mp4  # バイト完全一致

# (safetensors 専用) ファインチューニング済みモデルの差分圧縮(基準モデル指定)
./CatelliteCompressor c --base tuned.safetensors tuned_delta
# 復元(同じ base が必要)
./CatelliteCompressor d --base=tuned_delta.catcmp restored.safetensors
```

### テキスト / JSON / SQLite の可逆圧縮と検証

```bash
# テキスト (REV-BWT)、JSON (分割＋BWT)、SQLite (カラム分離) を自動選択
./CatelliteCompressor c source.txt source
./CatelliteCompressor d source.catcmp source_restored.txt

# バイト完全一致の確認 (SHA256)
sha256sum source.txt source_restored.txt

# ベンチマーク一式 (xz / zstd / 7z / gzip と比較、結果は results.csv)
# 注意: run.py はリポジトリ直下の ./CC バイナリを使用します
cp ./CatelliteCompressor ./CC
python3 run.py
```

---

## 仕組み

### CAT-Z (LZMA2 風汎用コーデック)

LZMA2 の設計思想をベースに、Nim でゼロから実装した可逆圧縮コーデックです。

- **バイナリツリー一致検索** — 8 MB ディクショナリ内で最長一致を探索(MaxChain=2048)
- **事象木符号化** — リテラル / マッチ / リピートを 12 状態の状態機械で符号化
  - リテラル: state×256 + prevLit でコンテキスト選択、一致済みリテラルも対応
  - マッチ: ZPosState + isRep + prevLenCls で選択
  - 長さ/オフセット: 可変長ツリー符号 + 符号化位置ビット
- **レンジコーディング** — 確率Models を PMove/ProbBits で自動最適化
  - pm ∈ {3,4,5,6,7}, pb ∈ {11,13,15} の 45 コンボをグリッドサーチ
  - Block DP (最適パーサ) + Flat (低オーバーヘッド) を自動選択
- **圧縮率**: ソースコード 74.7% / JSON 85.5% / SQLite DB 97.9% 削減

### CAT-VM 命令セット

ファイルを先頭から走査し、以下の 5 命令で再構成可能なストリームへ変換します。

| Op | 名前 | 意味 |
|----|------|------|
| 1 | `LIT` | 直後の 1 バイトをそのまま出力 |
| 2 | `LIT_LONG` | 長さ N のリテラル列を出力 |
| 3 | `RLE` | 1 バイトを N 回繰り返す |
| 4 | `MATCH` | 過去ウィンドウ内の N バイトをオフセットで参照 |
| 5 | `REPEAT` | 直前の MATCH 出力を N 回繰り返す |

### CAT-LZ (高密度 LZ)

8 項目ごとにフラグバイトを置き、リテラルを **9 ビット**、
一致を **17 ビット〜**(u16 オフセット + 可変長)に詰めた内蔵 LZ コーデックです。
長距離一致(64 KB ウィンドウ)と 255 エスケープによる超長一致に対応。

### テンソル量子化 (safetensors)

- テンソルごとの最大絶対値から対称スケールを算出し、INT8 / INT4 へ量子化
- スケールと元 dtype はヘッダの `__metadata__.__quant__` に記録
- 復元時はスケールで逆量子化し、**入力と同じ dtype** で safetensors を再構築
- 既定(auto)は FP16/INT8/INT4 の各出力サイズを厳密計算し最小を採用
  (同サイズなら高品質側を優先)。データ走査は 1 パスのみ

### MP4 ハンドラ

MP4 を `ftyp / moov / mdat / free ...` の box ツリーとして解析します。
各 box は `type, form, origSize, compSize, method` の 22 バイト record で
記録され、ペイロードは box ごとに RAW / CAT-VM / CAT-LZ を選択して保持されます。

---

## スマートモードとセーフモード

既定は **スマートモード**(非可逆変換含む+自動最適化)です。
`--safe` を指定すると一切の変換を行わず、常に完全可逆になります。

| 項目 | スマート (default) | セーフ (`--safe`) |
|------|--------------------|-------------------|
| 復元結果 | 変換対象は近似／それ以外は完全一致 | 全て元とバイト完全一致 |
| テンソル | 量子化(最小ビットを自動選択) | そのまま(CAT-Z/CAT-LZ/VM/RAW) |
| 用途 | 容量優先の保存 | アーカイブ・配布・検証 |

スマートモードの自動割り当て:

| 種別 | 入力例 | 変換先 | 性質 | 依存 |
|------|--------|--------|------|------|
| 動画 | .mp4/.mkv/.mov/.avi/... | .mp4 (H.264) | 非可逆 | ffmpeg(任意) |
| 画像 | .png/.jpg/.bmp/.gif/... | .webp | 非可逆 | ffmpeg(任意) |
| 音声 | .wav/.flac/.mp3/.ogg/... | .opus | 非可逆 | ffmpeg(任意) |
| 機械学習 | .safetensors 等 | INT量子化(復元時は入力と同じ dtype) | 非可逆 | (内蔵) |
| 3D モデル | .obj | 頂点座標の丸め | 非可逆 | (内蔵) |
| その他 | 全ファイル | 完全可逆(CAT-Z / CAT-LZ / CAT-VM 自動選択) | 可逆(バイト一致) | (内蔵) |

---

## ベンチマーク (実測)

| 入力 | モード | 結果 | 備考 |
|------|--------|------|------|
| ソースコード 191 KB | REV-BWT(可逆) | **18.2%** (81.8% 削減) | 完全可逆 |
| JSON 1.5 MB | JSON 分割＋BWT(可逆) | **6.5%** (93.5% 削減) | 完全可逆 |
| SQLite DB 2.1 MB | カラム分離(可逆) | **55.6%** (44.4% 削減) | 完全可逆 |
| LLM 重み BF16 5.33 GB | スマート(auto) | **16.8%** (75.0% 削減) | INT4 自動選択 (約4分) |
| 反復データ 1.9 GB | 可逆 | **99.97% 削減** | メモリ一定 |
| ランダム 1 MB | 可逆 | RAW 通過 (一致) | 膨張しない |
| MP4 20 KB | 可逆 | **98.3% 削減** | box 構造保持 |

### 他ツールとの比較 (実測)

同一ファイルを各ツールの最高設定で圧縮した比較です。
(`run.py` による自動ベンチマーク、Linux x86_64 / Nim 2.2.10 リリースビルド)

| ファイル | 元サイズ | ours(auto) | xz(-9) | 7z(-mx=9) | zstd(-19) | gzip(-9) |
|---|---:|---:|---:|---:|---:|---:|
| source.txt | 191,522 B | **18.19%** (34,847 B) | 18.51% | 18.55% | 19.31% | 21.16% |
| data.json | 1,522,293 B | **6.53%** (99,338 B) | 6.69% | 6.71% | 6.99% | 8.81% |
| data.db (SQLite) | 2,125,824 B | **55.59%** (1,181,680 B) | 57.53% | 57.66% | 60.20% | 63.10% |
| LLM 重み BF16 | 16 MB | **16.8%** | 70.6% | 70.7% | 78.0% | — |
| 動画 MP4 | 22 KB | **58.0%** | 92.0% | 92.3% | 91.4% | — |

- **テキスト・JSON・DB のすべてで xz / zstd / 7z / gzip に勝利**:
  テキストは REV-BWT、JSON は skeleton/keys/strs 分離＋skeleton の BWT、
  DB はレコードのカラム分離 (`dbcol`) により、各形式の構造的な冗長性を
  抽出してから符号化します。復元後は元のバイト列と完全一致します。
- **LLM 重みで圧倒的**: CAT-Z エントロピー段により BF16 の約 **6 分の 1**。
  復元は入力と同じ dtype(BF16)で推論に使用可能
- **動画でも優位**: ボックス構造を保持したまま圧縮

測定環境: Linux x86_64 / Nim 2.2.10 リリースビルド

---

## フォーマット (CATCOMP1)

```
マジック : "CATCOMP1" (8 bytes)
バージョン: 0x01
エントリ繰り返し:
  kind      : u8   (0=End, 1=Single, 2=Member)
  pathLen   : u8
  relPath   : pathLen bytes
  method    : u8   (0=RAW, 1=CAT-VM, 2=MP4, 3=LOSSY, 4=CAT-LZ, 5=CAT-Z)
  origSize  : u64le
  compSize  : u64le
  payload   : compSize bytes
```

CAT-Z エントリの payload は `[1 byte header: pm|pb]` + レンジコーディングされた
CAT-Z ストリームです。header の low 4 bits = ProbMove, high 4 bits = ProbBits。

LOSSY エントリの payload は `extLen + ext + innerMethod + transSize + 変換データ`
で、テンソルの場合は量子化済み safetensors(`__metadata__.__quant__` に bits /
scales / 元 dtype を保持)です。

---

## 注意事項

- `.catcmp` アーカイブを `c` の入力に渡すとエラーになります(二重圧縮の防止)。
  拡張子を変更してもマジック(`CATCOMP1`)で検出されます。
- テンソル量子化は非可逆です。品質が重要な場合は `--qbits=16`(FP16)か
  `--safe`(無変換)を使用してください。
- テンソル量子化は一時ファイルを作らないため、必要な空きディスクは
  「入力 + 出力」分のみ。メディア変換(ffmpeg 使用時)の一時ファイルは
  環境変数 `CATCOMP_TMP` で変更可能です(既定: `~/.catcc_tmp`)。
- 対応テンソル拡張子: `.safetensors` / `.safetensor` / `.bin`

---

## ライセンス

MIT License — 詳細は [LICENSE](./LICENSE) を参照してください。

---

## 寄付 / Donation

このツールが役に立ったら、開発の応援をよろしくお願いします!

<a href="https://buymeacoffee.com/yoinekodo_">
  <img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png"
       alt="Buy Me A Coffee"
       style="height: 41px !important; width: 174px !important; box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;">
</a>

URL: https://buymeacoffee.com/yoinekodo_
