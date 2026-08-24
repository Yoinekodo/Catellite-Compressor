# CatelliteCompressor

次世代パラダイム圧縮ツール。ファイル / ディレクトリを `.catcomp` アーカイブに
まとめ、独自のバイナリ生成命令セット **CAT-VM** で可逆圧縮を行います。

```
使い方:
  圧縮: ./CatelliteCompressor c [オプション] <入力(ファイル/Dir)> <出力>
  復元: ./CatelliteCompressor d <入力> <出力(ファイル/Dir)>

オプション:
  --lossy[=CRF]  動画を非可逆再符号化して格納(既定CRF=51, 0=高品質〜51=最小)
                 ※ 復元結果は元のファイルと同一にはなりません
```

`.catcomp` 拡張子は省略可能です。省略時は自動で付与します。

---

## 特徴

- **完全可逆 (CAT-VM)** — テキスト・ソースコード等の構造化データは命令ストリーム
  に変換して劇的に縮小。復元後は元のバイト列と **完全一致** します。
- **動画構造保管 (MP4 ハンドラ)** — MP4 を box 単位で解析し、圧縮済みの `mdat`
  等はそのまま保持、メタデータは可逆圧縮。動画品質は劣化しません。
- **非可逆モード (`--lossy`)** — 動画を ffmpeg で再符号化して格納。視覚的に同等な
  別ファイルとして保存し、元データとは異なることを明示します。
- **ストリーミング処理** — チャンク分割 + 256 MB メモリ上限で、数 GB の入力も安全に
  処理します。
- **誠実な圧縮率報告** — 膨張する入力(ランダムデータ等)は RAW のまま通過させ、
  「不可能を無理にねじ曲げる」ことはしません (後述)。

---

## インストール

Nim 2.x が必要です。

```bash
# nimble 経由
nimble build -d:release

# または直接
nim c -d:release --opt:speed -o:CatelliteCompressor src/CatelliteCompressor.nim
```

---

## 使用例

```bash
# ディレクトリを圧縮 (可逆)
./CatelliteCompressor c ./my_project ./archive
./CatelliteCompressor d ./archive.catcomp ./restored

# 単一ファイル (拡張子省略可)
./CatelliteCompressor c movie.mp4 out
./CatelliteCompressor d out movie_restored.mp4

# 動画を非可逆で大幅圧縮
./CatelliteCompressor c --lossy movie.mp4 small
./CatelliteCompressor c --lossy=40 movie.mp4 small40   # CRF 40 で高品質寄り
```

---

## 仕組み

### CAT-VM 命令セット

ファイルを先頭から走査し、以下の 5 命令で再構成可能なストリームへ変換します。

| Op | 名前 | 意味 |
|----|------|------|
| 1 | `LIT` | 直後の 1 バイトをそのまま出力 |
| 2 | `LIT_LONG` | 長さ N のリテラル列を出力 |
| 3 | `RLE` | 1 バイトを N 回繰り返す |
| 4 | `MATCH` | 過去ウィンドウ内の N バイトをオフセットで参照 |
| 5 | `REPEAT` | 直前の MATCH 出力を N 回繰り返す |

ハッシュ連想表で一致を検索、最小一致長 4 バイト以上を MATCH 化します。
エンコードとデコードは完全に対称です。

### MP4 ハンドラ

MP4 を `ftyp / moov / mdat / free ...` の box ツリーとして解析します。
各 box は `type, form, origSize, compSize, method` の 22 バイト record で
記録され、ペイロードは CAT-VM またはそのまま(RAW)保持されます。
box サイズ表現(`32bit` / `largesize` / `末尾まで`)の違いも正確に再現します。

### ストリーミング

入力を 1 MB のチャンクに分割し、各チャンク内の先頭 256 KB をサンプルして
VM / RAW を選択。チャンク間は MATCH ウィンドウを切り詰めつつ連続性を保ち、
メモリ使用量を 256 MB 以内に抑えます。

---

## 可逆モードと非可逆モード

| 項目 | 可逆 (default) | 非可逆 (`--lossy`) |
|------|----------------|-------------------|
| 復元結果 | 元とバイト一致 | 視覚・聴覚的に同等な別ファイル |
| 対応 | 全ファイル | 動画 (.mp4/.mkv/.mov 等) |
| 格納内容 | CAT-VM 命令 | ffmpeg 再符号化後のストリーム |
| 用途 | アーカイブ・配布 | 容量優先の軽量保存 |

`--lossy` は ffmpeg が無い場合、または再符号化しても元より大きくなる場合は
自動で可逆格納へフォールバックします。

---

## ベンチマーク (実測)

| 入力 | モード | 結果 | 備考 |
|------|--------|------|------|
| テキスト/ソース混合 56 KB | 可逆 | **99.01% 削減** | 完全一致 |
| 反復データ 1.9 GB | 可逆 | **99.97% 削減** (12 秒) | 256 MB メモリ内 |
| ランダム 50 MB | 可逆 | RAW 通過 (一致) | 膨張しない |
| MP4 16 MB | 可逆 | 0.05% 削減 (一致) | 構造保持 |
| MP4 16 MB | `--lossy` | **93.66% 削減** | CRF 51 |
| MP4 16 MB | `--lossy=40` | **86.1% 削減** | CRF 40 |

---

## 誠実さについて (情報理論の限界)

「どんなファイルでも 98% 圧縮」は、**真にランダムなデータに対しては数学的に
不可能** です (シャノンの情報理論)。本ツールは:

- 構造を持つデータ → 命令化で劇的に縮小
- 既に圧縮済み / 無秩序なデータ → RAW で通過 (無駄な膨張を防ぐ)

という設計をとり、実測値を正直に報告します。「不可能をできるふり」はしません。

---

## フォーマット (CATCOMP2)

```
マジック : "CATCOMP2" (8 bytes)
バージョン: 0x02
エントリ繰り返し:
  kind      : u8   (0=End, 1=Single, 2=Member)
  pathLen   : u8
  relPath   : pathLen bytes
  method    : u8   (0=RAW, 1=VM, 2=MP4, 3=LOSSY)
  origSize  : u64le
  compSize  : u64le
  payload   : compSize bytes
```

---

## ライセンス

MIT License — 詳細は [LICENSE](./LICENSE) を参照してください。
