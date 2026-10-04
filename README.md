# Volatility 3 uTorrent resume.dat carver

[![Tests](https://github.com/berm0427/volatility3-utorrentresume/actions/workflows/tests.yml/badge.svg)](https://github.com/berm0427/volatility3-utorrentresume/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 한국어 소개

Windows 메모리 덤프에서 uTorrent/BitTorrent의 bencode 기반 `resume.dat`
흔적을 복구하는 Volatility 3 플러그인입니다. 실행 중인 프로세스에서는
VAD를 검사하고, 프로세스가 완전히 종료된 경우에는 물리 메모리 전체에서
남아 있는 조각을 카빙하여 서로 연관된 레코드를 보수적으로 결합합니다.

복구 가능한 주요 항목은 다음과 같습니다.

- 토렌트 이름과 저장 경로
- SHA-1/SHA-256 InfoHash
- 트래커 및 웹 시드 URL
- 다운로드·업로드·낭비 바이트와 속도
- 완료 조각 수, 실행 시간 및 시드 시간
- IPv4/IPv6 피어 주소와 포트
- 추가·완료 시각 및 클라이언트 상태 값
- 복구 출처, 신뢰도, 결합된 메모리 조각 수

InfoHash, 파일명이나 특정 배포판 이름을 하드코딩하지 않습니다. 물리 메모리
조각을 결합할 때도 후보가 하나로 특정되는 경우에만 연결하며, 같은 크기의
후보가 여러 개이면 오귀속을 피하기 위해 별도 결과로 남깁니다.

### 기본 사용법

플러그인을 `volatility3/framework/plugins/windows/utorrentresume.py`에 복사한
후 다음과 같이 실행합니다.

```powershell
python .\vol.py `
  -f 'C:\path\memory.raw' `
  windows.utorrentresume.UtorrentResume
```

CSV로 저장하려면 다음과 같이 실행합니다.

```powershell
python .\vol.py -q -r csv `
  -f 'C:\path\memory.raw' `
  windows.utorrentresume.UtorrentResume |
  Set-Content -Path '.\utorrent-results.csv' -Encoding utf8
```

`-q`는 진행 메시지만 숨기며 탐지 결과에는 영향을 주지 않습니다. 피어 주소가
복구되었다고 해서 해당 피어와 실제 파일 조각이 교환됐다는 사실까지 단독으로
입증하는 것은 아닙니다.

---

This Windows plugin searches the virtual address descriptors of official
`uTorrent.exe` and `BitTorrent.exe` processes for bencoded `resume.dat` keys,
validates the surrounding bencode object, and emits recovered torrent metadata.
If no process record is recovered, it automatically scans the base physical
memory layer for stale records left after the process exited. The physical
fallback can recover and correlate partial key/value fragments when the outer
bencode dictionary was already damaged or freed.

It deliberately does not assume that a `_FILE_OBJECT` offset is also a readable
file-data address. That was the main reliability problem in the earlier
`filescan`/`poolscanner` approach. It also does not use a fixed footer or a regex
such as `key + newline + 8 bytes`; normal uTorrent resume data is bencoded and
must be parsed according to its length and integer delimiters.

## Installation

Copy `utorrentresume.py` into the installed Volatility tree:

```text
volatility3/framework/plugins/windows/utorrentresume.py
```

Alternatively, point Volatility at this directory. In that layout the plugin
name does not include the `windows.` package prefix:

```bash
python vol.py --plugin-dirs /path/to/volatility3-utorrentresume \
  -f memory.raw utorrentresume.UtorrentResume
```

The implementation was import-tested against Volatility 3 `2.28.2` and declares
`PsList >= 3.0.0`.

## Usage

```bash
python vol.py -f memory.raw windows.utorrentresume.UtorrentResume
```

Scan an explicitly selected process even if its image name is not selected by
the default `auto` mode:

```bash
python vol.py -f memory.raw windows.utorrentresume.UtorrentResume --pid 1234
```

Change the expected process name, or provide comma-separated names:

```bash
python vol.py -f memory.raw windows.utorrentresume.UtorrentResume \
  --process-name utorrent.exe,bittorrent.exe
```

Useful tuning options:

- `--lookbehind`: bytes read before each matching bencode key (default 1 MiB)
- `--lookahead`: bytes read after each key (default 4 MiB)
- `--max-results`: maximum number of unique records (default 1000)
- `--scan-physical`: scan physical memory even if live-process results exist
- `--physical-fallback`: automatically scan physical memory when the VAD search
  has no results (enabled by default)

For machine-readable output, combine the command with Volatility's JSON or CSV
renderer.

## Output fields

- PID and process image name
- validated bencode record and anchor virtual offsets
- torrent dictionary key, caption, and local path
- info-hash when an actual 20-byte v1 or 32-byte v2 hash is recovered; legacy
  uTorrent/BitTorrent resume records commonly store it in the `info` field
- tracker and web-seed URLs
- downloaded/uploaded counters
- wasted bytes, speeds, hash failures, completed-piece bit count, runtime, seed
  time, desired-ratio raw value, and client state flags
- compact IPv4 `peers` and IPv6 `peers6` decoded as normalized `IP:port`,
  including IPv4-mapped IPv6 conversion and address-class counts
- added/completed and record timestamps normalized to UTC when valid;
  duration-like fields remain explicitly labeled as seconds or raw values
- recovery mode, confidence, unique fragment count, and recovered-key list

## Limitations

- The `Source` column distinguishes `ProcessVAD` virtual offsets from
  `PhysicalMemory` physical offsets. Physical results use PID `-1` because a
  stale page cannot be attributed reliably to its former process.
- Physical fragments belonging to the same torrent are correlated using the
  caption or the basename of the recovered local path. An orphan `info`/`known`
  fragment may also be joined when its piece-state vector length identifies
  exactly one named torrent; ambiguous same-sized candidates are deliberately
  left separate. Numeric counters use the greatest recovered value and compact
  peer entries are deduplicated.
- `InfoHash` remains blank unless the memory record contains a valid 20-byte,
  32-byte, 40-hex-character, or 64-hex-character value. The plugin never hashes
  a filename or damaged fragment and labels it as the torrent info-hash.
- Peer entries show cached or previously connected endpoints. Their presence
  alone does not prove that payload data was exchanged with each endpoint.
- Closing the window may leave uTorrent running in the notification area. If
  the process really exited, physical recovery only works until the freed pages
  are overwritten or excluded from the acquisition.
- Page loss, compression, or a record split across unavailable pages can prevent
  complete bencode validation.
- uTorrent versions may add fields; unknown bencode keys remain harmless but are
  not displayed.
- The VAD path was validated against a real BitTorrent.exe memory image. The
  physical fallback remains best-effort because a virtual bencode record can
  span physically non-contiguous pages.

## Tests

From this directory, with Volatility available on `PYTHONPATH`:

```bash
python -m unittest -v test_utorrentresume.py
```

The physical fallback can also be exercised without a real dump:

```bash
python test_mock_integration.py
```

This synthetic test places a complete resume record in a fake physical layer,
verifies carving, and checks that the generator emits `PhysicalMemory` with PID
`-1` when no process is available. Additional multi-torrent tests verify that
orphan info-hash fragments are joined only when the piece-vector length maps to
one torrent, and remain separate when same-sized candidates are ambiguous.
