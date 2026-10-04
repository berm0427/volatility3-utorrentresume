"""Volatility 3 plugin for carving uTorrent resume.dat records from memory.

Copy this file to ``volatility3/framework/plugins/windows/utorrentresume.py``
or load its parent directory with Volatility's ``--plugin-dirs``/``-p`` option.
"""

import datetime
import ipaddress
import logging
import ntpath
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist


vollog = logging.getLogger(__name__)


class BencodeError(ValueError):
    """Raised when a byte sequence is not a complete, valid bencode value."""


class BencodeParser:
    """Small defensive bencode parser suitable for untrusted memory bytes."""

    def __init__(
        self,
        data: bytes,
        *,
        max_depth: int = 64,
        max_items: int = 100_000,
        max_string: int = 16 * 1024 * 1024,
    ) -> None:
        self.data = data
        self.max_depth = max_depth
        self.max_items = max_items
        self.max_string = max_string
        self.items = 0

    def parse(self, offset: int = 0) -> Tuple[Any, int]:
        return self._parse(offset, 0)

    def _parse(self, offset: int, depth: int) -> Tuple[Any, int]:
        if depth > self.max_depth:
            raise BencodeError("maximum nesting depth exceeded")
        if offset >= len(self.data):
            raise BencodeError("unexpected end of data")

        self.items += 1
        if self.items > self.max_items:
            raise BencodeError("maximum item count exceeded")

        marker = self.data[offset]
        if marker == ord("i"):
            return self._parse_integer(offset)
        if marker == ord("l"):
            return self._parse_list(offset, depth)
        if marker == ord("d"):
            return self._parse_dict(offset, depth)
        if ord("0") <= marker <= ord("9"):
            return self._parse_bytes(offset)
        raise BencodeError(f"invalid marker 0x{marker:02x} at {offset:#x}")

    def _parse_integer(self, offset: int) -> Tuple[int, int]:
        end = self.data.find(b"e", offset + 1)
        if end < 0:
            raise BencodeError("unterminated integer")
        raw = self.data[offset + 1 : end]
        if not raw or raw == b"-0" or (raw.startswith(b"0") and len(raw) > 1):
            raise BencodeError("invalid integer")
        try:
            return int(raw), end + 1
        except ValueError as exc:
            raise BencodeError("invalid integer digits") from exc

    def _parse_bytes(self, offset: int) -> Tuple[bytes, int]:
        colon = self.data.find(b":", offset, min(len(self.data), offset + 24))
        if colon < 0:
            raise BencodeError("missing byte-string separator")
        raw_length = self.data[offset:colon]
        if not raw_length or (raw_length.startswith(b"0") and len(raw_length) > 1):
            raise BencodeError("invalid byte-string length")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise BencodeError("invalid byte-string length digits") from exc
        if length > self.max_string:
            raise BencodeError("byte string exceeds configured limit")
        end = colon + 1 + length
        if end > len(self.data):
            raise BencodeError("truncated byte string")
        return self.data[colon + 1 : end], end

    def _parse_list(self, offset: int, depth: int) -> Tuple[List[Any], int]:
        result: List[Any] = []
        cursor = offset + 1
        while True:
            if cursor >= len(self.data):
                raise BencodeError("unterminated list")
            if self.data[cursor] == ord("e"):
                return result, cursor + 1
            value, cursor = self._parse(cursor, depth + 1)
            result.append(value)

    def _parse_dict(self, offset: int, depth: int) -> Tuple[Dict[bytes, Any], int]:
        result: Dict[bytes, Any] = {}
        cursor = offset + 1
        while True:
            if cursor >= len(self.data):
                raise BencodeError("unterminated dictionary")
            if self.data[cursor] == ord("e"):
                return result, cursor + 1
            key, cursor = self._parse_bytes(cursor)
            value, cursor = self._parse(cursor, depth + 1)
            result[key] = value


@dataclass(frozen=True)
class TorrentRecord:
    source_offset: int
    name: bytes
    values: Dict[bytes, Any]
    recovery_mode: str = "CompleteBencode"
    fragment_count: int = 1


INTERESTING_KEYS = {
    b"added_on",
    b"caption",
    b"completed_on",
    b"downloaded",
    b"downspeed",
    b"hashed",
    b"have",
    b"info",
    b"info_hash",
    b"known",
    b"last_active",
    b"last seen complete",
    b"path",
    b"peers",
    b"peers6",
    b"runtime",
    b"seedtime",
    b"trackers",
    b"uploaded",
    b"upspeed",
    b"waste",
}

ANCHORS = [
    b"8:added_on",
    b"7:caption",
    b"10:completed_on",
    b"10:downloaded",
    b"9:downspeed",
    b"4:info",
    b"9:info_hash",
    b"11:last_active",
    b"18:last seen complete",
    b"4:path",
    b"5:peers",
    b"6:peers6",
    b"7:runtime",
    b"8:seedtime",
    b"8:trackers",
    b"8:uploaded",
    b"7:upspeed",
    b"5:waste",
]

KNOWN_PROCESS_NAMES = {"utorrent.exe", "bittorrent.exe"}


def _record_score(value: Dict[bytes, Any]) -> int:
    return len(INTERESTING_KEYS.intersection(value.keys()))


def _walk_records(
    value: Any, source_offset: int, parent_key: bytes = b""
) -> Iterator[TorrentRecord]:
    if isinstance(value, dict):
        if _record_score(value) >= 2:
            yield TorrentRecord(source_offset, parent_key, value)
        for key, child in value.items():
            if isinstance(child, (dict, list)):
                yield from _walk_records(child, source_offset, key)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_records(child, source_offset, parent_key)


def carve_records(
    data: bytes,
    anchor_index: int,
    absolute_start: int,
    max_candidates: int = 4096,
) -> List[TorrentRecord]:
    """Finds the nearest complete bencode dictionaries enclosing an anchor."""

    candidates: List[int] = []
    cursor = anchor_index
    while cursor >= 0 and len(candidates) < max_candidates:
        cursor = data.rfind(b"d", 0, cursor + 1)
        if cursor < 0:
            break
        candidates.append(cursor)
        cursor -= 1

    best_unnamed: List[TorrentRecord] = []
    for start in candidates:
        try:
            value, end = BencodeParser(data).parse(start)
        except BencodeError:
            continue
        if not (start <= anchor_index < end):
            continue
        records = list(_walk_records(value, absolute_start + start))
        if any(record.name for record in records):
            return records
        if records and not best_unnamed:
            best_unnamed = records
    return best_unnamed


def carve_fragment_records(
    data: bytes,
    anchor_index: int,
    absolute_start: int,
) -> List[TorrentRecord]:
    """Recovers a contiguous bencode key/value fragment without its outer dict."""

    candidate_starts = set()
    for anchor in ANCHORS:
        cursor = data.rfind(anchor, 0, anchor_index + len(anchor))
        if cursor >= 0:
            candidate_starts.add(cursor)

    best: Optional[TorrentRecord] = None
    best_score = 0
    for start in sorted(candidate_starts):
        parser = BencodeParser(data)
        cursor = start
        values: Dict[bytes, Any] = {}
        try:
            while cursor < len(data) and data[cursor] != ord("e"):
                key, cursor = parser._parse_bytes(cursor)
                value, cursor = parser.parse(cursor)
                values[key] = value
        except BencodeError:
            pass

        score = _record_score(values)
        if score >= 2 and score > best_score:
            best = TorrentRecord(
                absolute_start + start,
                b"",
                values,
                recovery_mode="Fragment",
            )
            best_score = score

    return [best] if best is not None else []


def _display(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _integer(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, bytes):
        try:
            return int(value)
        except ValueError:
            if len(value) in (4, 8):
                return int.from_bytes(value, "little")
    return 0


def _timestamp(value: Any) -> str:
    number = _integer(value)
    if number <= 0:
        return ""
    try:
        return datetime.datetime.fromtimestamp(
            number, tz=datetime.timezone.utc
        ).isoformat()
    except (OverflowError, OSError, ValueError):
        return str(number)


def _format_compact_peers(value: Any, address_size: int) -> str:
    """Formats BitTorrent compact peers as ``IP:port`` entries."""

    if not isinstance(value, bytes):
        return ""
    entry_size = address_size + 2
    if not value or len(value) % entry_size:
        return ""

    peers: List[str] = []
    for cursor in range(0, len(value), entry_size):
        entry = value[cursor : cursor + entry_size]
        try:
            address_object = ipaddress.ip_address(entry[:address_size])
        except ValueError:
            continue
        if isinstance(address_object, ipaddress.IPv6Address) and address_object.ipv4_mapped:
            address_object = address_object.ipv4_mapped
        address = str(address_object)
        port = int.from_bytes(entry[address_size:], "big")
        if port <= 0:
            continue
        if isinstance(address_object, ipaddress.IPv6Address):
            peers.append(f"[{address}]:{port}")
        else:
            peers.append(f"{address}:{port}")
    return "; ".join(peers)


def _peer_classes(*values: Tuple[Any, int]) -> str:
    counts: Dict[str, int] = {}
    seen = set()
    for value, address_size in values:
        if not isinstance(value, bytes):
            continue
        entry_size = address_size + 2
        if len(value) % entry_size:
            continue
        for cursor in range(0, len(value), entry_size):
            entry = value[cursor : cursor + entry_size]
            if entry in seen:
                continue
            seen.add(entry)
            try:
                address = ipaddress.ip_address(entry[:address_size])
            except ValueError:
                continue
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            if address.is_loopback:
                label = "Loopback"
            elif address.is_link_local:
                label = "LinkLocal"
            elif address.is_private:
                label = "Private"
            elif address.is_multicast:
                label = "Multicast"
            elif address.is_global:
                label = "Public"
            else:
                label = "Reserved"
            counts[label] = counts.get(label, 0) + 1
    return "; ".join(f"{key}={counts[key]}" for key in sorted(counts))


def _format_list(value: Any) -> str:
    if not isinstance(value, list):
        return ""
    rendered = []
    for item in value:
        text = _display(item).strip()
        if text and text not in rendered:
            rendered.append(text)
    return "; ".join(rendered)


def _web_seeds(values: Dict[bytes, Any]) -> str:
    for key in (b"webseeds", b"web_seeds", b"url-list"):
        value = values.get(key)
        if isinstance(value, list):
            return _format_list(value)
        if value:
            return _display(value)
    return ""


def _info_hash(values: Dict[bytes, Any]) -> str:
    value = values.get(b"info_hash")
    if not isinstance(value, bytes):
        value = values.get(b"info")
    if not isinstance(value, bytes):
        return ""
    if len(value) in (20, 32):
        return value.hex()
    try:
        text = value.decode("ascii").strip().lower()
    except UnicodeDecodeError:
        return ""
    if len(text) in (40, 64) and all(character in "0123456789abcdef" for character in text):
        return text
    return ""


def _info_hash_source(values: Dict[bytes, Any]) -> str:
    if _info_hash(values):
        if isinstance(values.get(b"info_hash"), bytes):
            return "info_hash"
        if isinstance(values.get(b"info"), bytes):
            return "info"
    return ""


def _completed_pieces(value: Any) -> int:
    if not isinstance(value, bytes):
        return 0
    return sum(byte.bit_count() for byte in value)


def _confidence(record: TorrentRecord) -> str:
    score = _record_score(record.values)
    has_identity = bool(_fragment_identity(record))
    if record.recovery_mode == "CompleteBencode" and score >= 2:
        return "High"
    if record.fragment_count >= 2 and has_identity and score >= 4:
        return "High"
    if has_identity and score >= 2:
        return "Medium"
    return "Low"


def _record_fields(record: TorrentRecord) -> Tuple[Any, ...]:
    values = record.values
    return (
        _display(record.name),
        _display(values.get(b"caption")),
        _display(values.get(b"path")),
        _info_hash(values),
        _info_hash_source(values),
        _format_list(values.get(b"trackers")),
        _web_seeds(values),
        _integer(values.get(b"downloaded")),
        _integer(values.get(b"uploaded")),
        _integer(values.get(b"waste")),
        _integer(values.get(b"downspeed")),
        _integer(values.get(b"upspeed")),
        _integer(values.get(b"hashfails")),
        _completed_pieces(values.get(b"have")),
        _integer(values.get(b"runtime")),
        _integer(values.get(b"seedtime")),
        _integer(values.get(b"wanted_ratio")),
        _integer(values.get(b"started")),
        _integer(values.get(b"valid")),
        _integer(values.get(b"wasforce")),
        _integer(values.get(b"superseed")),
        _integer(values.get(b"share_mode")),
        _integer(values.get(b"use_utp")),
        _format_compact_peers(values.get(b"peers"), 4),
        _format_compact_peers(values.get(b"peers6"), 16),
        _peer_classes((values.get(b"peers"), 4), (values.get(b"peers6"), 16)),
        _timestamp(values.get(b"added_on")),
        _timestamp(values.get(b"completed_on")),
        _integer(values.get(b"last_active")),
        _integer(values.get(b"last seen complete")),
        _timestamp(values.get(b"time")),
        record.recovery_mode,
        _confidence(record),
        record.fragment_count,
        "; ".join(sorted(_display(key) for key in values if key in INTERESTING_KEYS)),
    )


def _fragment_identity(record: TorrentRecord) -> str:
    values = record.values
    caption = _display(values.get(b"caption")).strip()
    path = _display(values.get(b"path")).strip()
    name = _display(record.name).strip()
    return (caption or ntpath.basename(path) or name).casefold()


def _record_bitfields(record: TorrentRecord) -> List[bytes]:
    bitfields = []
    for key in (b"known", b"have", b"hashed"):
        value = record.values.get(key)
        if isinstance(value, bytes) and len(value) >= 8 and value not in bitfields:
            bitfields.append(value)
    return bitfields


def _unique_bitfield_owner(
    record: TorrentRecord,
    exact_owners: Dict[bytes, set],
    length_owners: Dict[int, set],
) -> str:
    candidates = set()
    bitfields = _record_bitfields(record)
    for bitfield in bitfields:
        candidates.update(exact_owners.get(bitfield, set()))
    if not candidates:
        for bitfield in bitfields:
            candidates.update(length_owners.get(len(bitfield), set()))
    return next(iter(candidates)) if len(candidates) == 1 else ""


def _merge_compact_peers(left: Any, right: Any, address_size: int) -> Any:
    entry_size = address_size + 2
    entries = []
    seen = set()
    for value in (left, right):
        if not isinstance(value, bytes) or len(value) % entry_size:
            continue
        for cursor in range(0, len(value), entry_size):
            entry = value[cursor : cursor + entry_size]
            if entry not in seen:
                seen.add(entry)
                entries.append(entry)
    return b"".join(entries)


def _merge_fragment_values(left: Dict[bytes, Any], right: Dict[bytes, Any]) -> None:
    for key, value in right.items():
        if key in (
            b"downloaded",
            b"uploaded",
            b"completed_on",
            b"last_active",
            b"last seen complete",
            b"runtime",
            b"seedtime",
            b"waste",
            b"downspeed",
            b"upspeed",
            b"hashfails",
            b"time",
        ):
            if _integer(value) > _integer(left.get(key)):
                left[key] = value
        elif key == b"added_on":
            current = _integer(left.get(key))
            candidate = _integer(value)
            if candidate > 0 and (current <= 0 or candidate < current):
                left[key] = value
        elif key == b"peers":
            left[key] = _merge_compact_peers(left.get(key), value, 4)
        elif key == b"peers6":
            left[key] = _merge_compact_peers(left.get(key), value, 16)
        elif key in (b"trackers", b"webseeds", b"web_seeds", b"url-list"):
            existing = left.get(key)
            combined = []
            for collection in (existing, value):
                items = collection if isinstance(collection, list) else [collection]
                for item in items:
                    if item not in (None, b"", "") and item not in combined:
                        combined.append(item)
            left[key] = combined
        elif key not in left or left[key] in (b"", "", None):
            left[key] = value


class UtorrentResume(interfaces.plugins.PluginInterface):
    """Carves uTorrent/BitTorrent resume records from process or physical memory."""

    _required_framework_version = (2, 4, 0)
    _version = (1, 6, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.ListRequirement(
                name="pid",
                description="Process IDs to include",
                element_type=int,
                optional=True,
            ),
            requirements.StringRequirement(
                name="process_name",
                description=(
                    "Process image name(s) to scan, comma-separated; "
                    "'auto' selects uTorrent and BitTorrent"
                ),
                default="auto",
                optional=True,
            ),
            requirements.IntRequirement(
                name="lookbehind",
                description="Bytes to read before each bencode key hit",
                default=1024 * 1024,
                optional=True,
            ),
            requirements.IntRequirement(
                name="lookahead",
                description="Bytes to read after each bencode key hit",
                default=4 * 1024 * 1024,
                optional=True,
            ),
            requirements.IntRequirement(
                name="max_results",
                description="Maximum number of unique records to emit",
                default=1000,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="physical_fallback",
                description=(
                    "Scan physical memory when no records are recovered from "
                    "a selected torrent process"
                ),
                default=True,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="scan_physical",
                description=(
                    "Always scan physical memory, even when process VAD records exist"
                ),
                default=False,
                optional=True,
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
        ]

    def _selected_processes(self) -> Iterable[Any]:
        pid_filter = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        configured_names = self.config.get("process_name", "auto").casefold()
        wanted_names = {
            item.strip() for item in configured_names.split(",") if item.strip()
        }
        if not wanted_names or "auto" in wanted_names:
            wanted_names = KNOWN_PROCESS_NAMES
        explicit_pids = bool(self.config.get("pid", None))

        for proc in pslist.PsList.list_processes(
            self.context, self.config["kernel"], filter_func=pid_filter
        ):
            name = utility.array_to_string(proc.ImageFileName)
            if explicit_pids or name.casefold() in wanted_names:
                yield proc

    @staticmethod
    def _vad_sections(proc: Any) -> List[Tuple[int, int]]:
        sections: List[Tuple[int, int]] = []
        for vad in proc.get_vad_root().traverse():
            try:
                start = int(vad.get_start())
                end = int(vad.get_end())
            except (AttributeError, exceptions.InvalidAddressException):
                continue
            if end >= start:
                sections.append((start, end - start + 1))
        return sections

    @staticmethod
    def _containing_section(
        offset: int, sections: Sequence[Tuple[int, int]]
    ) -> Optional[Tuple[int, int]]:
        for start, size in sections:
            if start <= offset < start + size:
                return start, size
        return None

    def _scan_process(self, proc: Any) -> Iterator[Tuple[int, TorrentRecord]]:
        layer_name = proc.add_process_layer()
        layer = self.context.layers[layer_name]
        sections = self._vad_sections(proc)
        scanner = scanners.MultiStringScanner(ANCHORS)
        lookbehind = max(0, int(self.config.get("lookbehind", 1024 * 1024)))
        lookahead = max(1, int(self.config.get("lookahead", 4 * 1024 * 1024)))

        for hit_offset, _pattern in layer.scan(
            self.context,
            scanner,
            progress_callback=self._progress_callback,
            sections=sections,
        ):
            section = self._containing_section(hit_offset, sections)
            if section is None:
                continue
            vad_start, vad_size = section
            vad_end = vad_start + vad_size
            read_start = max(vad_start, hit_offset - lookbehind)
            read_end = min(vad_end, hit_offset + lookahead)
            try:
                data = layer.read(read_start, read_end - read_start, pad=True)
            except exceptions.InvalidAddressException:
                continue
            relative_hit = hit_offset - read_start
            for record in carve_records(data, relative_hit, read_start):
                yield hit_offset, record

    def _scan_physical(self) -> Iterator[Tuple[int, TorrentRecord]]:
        """Scans the base physical-memory layer for stale bencode records."""

        kernel = self.context.modules[self.config["kernel"]]
        kernel_layer = self.context.layers[kernel.layer_name]
        memory_layer_name = kernel_layer.config.get("memory_layer", None)
        if not memory_layer_name or memory_layer_name not in self.context.layers:
            vollog.warning("Unable to locate the base physical-memory layer")
            return

        layer = self.context.layers[memory_layer_name]
        scanner = scanners.MultiStringScanner(ANCHORS)
        lookbehind = max(0, int(self.config.get("lookbehind", 1024 * 1024)))
        lookahead = max(1, int(self.config.get("lookahead", 4 * 1024 * 1024)))
        lower_bound = int(layer.minimum_address)
        upper_bound = int(layer.maximum_address) + 1

        for hit_offset, _pattern in layer.scan(
            self.context,
            scanner,
            progress_callback=self._progress_callback,
        ):
            read_start = max(lower_bound, int(hit_offset) - lookbehind)
            read_end = min(upper_bound, int(hit_offset) + lookahead)
            if read_end <= read_start:
                continue
            try:
                data = layer.read(read_start, read_end - read_start, pad=True)
            except exceptions.InvalidAddressException:
                continue
            relative_hit = int(hit_offset) - read_start
            records = carve_records(data, relative_hit, read_start)
            if not records:
                records = carve_fragment_records(data, relative_hit, read_start)
            for record in records:
                yield int(hit_offset), record

    def _generator(self):
        seen = set()
        emitted = 0
        process_emitted = 0
        maximum = max(1, int(self.config.get("max_results", 1000)))

        for proc in self._selected_processes():
            pid = int(proc.UniqueProcessId)
            process_name = utility.array_to_string(proc.ImageFileName)
            try:
                records = self._scan_process(proc)
                for hit_offset, record in records:
                    values = record.values
                    identity = (
                        pid,
                        record.source_offset,
                        record.name,
                        values.get(b"caption", b""),
                        values.get(b"path", b""),
                    )
                    if identity in seen:
                        continue
                    seen.add(identity)

                    yield 0, (
                        "ProcessVAD",
                        pid,
                        process_name,
                        format_hints.Hex(record.source_offset),
                        format_hints.Hex(hit_offset),
                        *_record_fields(record),
                    )
                    emitted += 1
                    process_emitted += 1
                    if emitted >= maximum:
                        return
            except exceptions.InvalidAddressException as exc:
                vollog.debug("Unable to scan PID %d: %s", pid, exc)

        use_fallback = self.config.get("physical_fallback", True) and not process_emitted
        if not (use_fallback or self.config.get("scan_physical", False)):
            return

        physical_records = list(self._scan_physical())
        seen_physical_fragments = set()
        unique_physical_records: List[Tuple[int, TorrentRecord]] = []
        for hit_offset, record in physical_records:
            fragment_identity = (
                record.source_offset,
                record.recovery_mode,
                _fragment_identity(record),
                tuple(sorted(record.values.keys())),
            )
            if fragment_identity in seen_physical_fragments:
                continue
            seen_physical_fragments.add(fragment_identity)
            unique_physical_records.append((hit_offset, record))

        bitfield_owners: Dict[bytes, set] = {}
        bitfield_length_owners: Dict[int, set] = {}
        for _hit_offset, record in unique_physical_records:
            owner = _fragment_identity(record)
            if not owner:
                continue
            for bitfield in _record_bitfields(record):
                bitfield_owners.setdefault(bitfield, set()).add(owner)
                bitfield_length_owners.setdefault(len(bitfield), set()).add(owner)

        merged_records: Dict[str, Tuple[int, TorrentRecord]] = {}
        for hit_offset, record in unique_physical_records:
            key = _fragment_identity(record)
            if not key:
                key = _unique_bitfield_owner(
                    record, bitfield_owners, bitfield_length_owners
                )
            key = key or f"offset:{record.source_offset:x}"
            if key not in merged_records:
                merged_records[key] = (
                    hit_offset,
                    TorrentRecord(
                        record.source_offset,
                        record.name,
                        dict(record.values),
                        recovery_mode=record.recovery_mode,
                        fragment_count=record.fragment_count,
                    ),
                )
                continue
            old_hit, old_record = merged_records[key]
            _merge_fragment_values(old_record.values, record.values)
            merged_mode = (
                "CorrelatedFragments"
                if old_record.recovery_mode != "CompleteBencode"
                or record.recovery_mode != "CompleteBencode"
                else "CompleteBencode"
            )
            merged_records[key] = (
                min(old_hit, hit_offset),
                TorrentRecord(
                    old_record.source_offset,
                    old_record.name or record.name,
                    old_record.values,
                    recovery_mode=merged_mode,
                    fragment_count=old_record.fragment_count + record.fragment_count,
                ),
            )

        for hit_offset, record in merged_records.values():
            values = record.values
            identity = (
                "physical",
                record.source_offset,
                record.name,
                values.get(b"caption", b""),
                values.get(b"path", b""),
            )
            if identity in seen:
                continue
            seen.add(identity)
            yield 0, (
                "PhysicalMemory",
                -1,
                "PhysicalMemory",
                format_hints.Hex(record.source_offset),
                format_hints.Hex(hit_offset),
                *_record_fields(record),
            )
            emitted += 1
            if emitted >= maximum:
                return

    def run(self):
        return renderers.TreeGrid(
            [
                ("Source", str),
                ("PID", int),
                ("Process", str),
                ("RecordOffset", format_hints.Hex),
                ("AnchorOffset", format_hints.Hex),
                ("Torrent", str),
                ("Caption", str),
                ("Path", str),
                ("InfoHash", str),
                ("InfoHashSource", str),
                ("Trackers", str),
                ("WebSeeds", str),
                ("Downloaded", int),
                ("Uploaded", int),
                ("Waste", int),
                ("DownSpeed", int),
                ("UpSpeed", int),
                ("HashFails", int),
                ("CompletedPieces", int),
                ("RuntimeSeconds", int),
                ("SeedTimeSeconds", int),
                ("WantedRatioRaw", int),
                ("StartedState", int),
                ("Valid", int),
                ("Forced", int),
                ("SuperSeed", int),
                ("ShareMode", int),
                ("UseUTP", int),
                ("Peers", str),
                ("Peers6", str),
                ("PeerClasses", str),
                ("AddedUTC", str),
                ("CompletedUTC", str),
                ("LastActiveSeconds", int),
                ("LastSeenCompleteRaw", int),
                ("RecordTimeUTC", str),
                ("RecoveryMode", str),
                ("Confidence", str),
                ("FragmentCount", int),
                ("RecoveredKeys", str),
            ],
            self._generator(),
        )
