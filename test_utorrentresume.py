import importlib.util
import pathlib
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("utorrentresume.py")
SPEC = importlib.util.spec_from_file_location("utorrentresume", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def bstr(value: bytes) -> bytes:
    return str(len(value)).encode() + b":" + value


def bint(value: int) -> bytes:
    return b"i" + str(value).encode() + b"e"


def bdict(items):
    return b"d" + b"".join(bstr(key) + value for key, value in items) + b"e"


class BencodeTests(unittest.TestCase):
    def test_formats_ipv4_and_ipv6_compact_peers(self):
        ipv4 = bytes([192, 0, 2, 10]) + (6881).to_bytes(2, "big")
        ipv6 = bytes.fromhex("20010db8000000000000000000000001") + (51413).to_bytes(2, "big")
        self.assertEqual(
            MODULE._format_compact_peers(ipv4, 4), "192.0.2.10:6881"
        )
        self.assertEqual(
            MODULE._format_compact_peers(ipv6, 16), "[2001:db8::1]:51413"
        )

    def test_normalizes_ipv4_mapped_ipv6_peer(self):
        mapped = bytes.fromhex("00000000000000000000ffffc0000201") + (6881).to_bytes(2, "big")
        self.assertEqual(MODULE._format_compact_peers(mapped, 16), "192.0.2.1:6881")

    def test_formats_forensic_metadata(self):
        info_hash = bytes(range(20))
        values = {
            b"info_hash": info_hash,
            b"trackers": [b"https://tracker.example/announce"],
            b"have": b"\x81",
        }
        self.assertEqual(MODULE._info_hash(values), info_hash.hex())
        self.assertEqual(
            MODULE._format_list(values[b"trackers"]),
            "https://tracker.example/announce",
        )
        self.assertEqual(MODULE._completed_pieces(values[b"have"]), 2)

    def test_extracts_resume_info_field_as_infohash(self):
        info_hash = bytes(range(20))
        values = {b"info": info_hash}
        self.assertEqual(MODULE._info_hash(values), info_hash.hex())
        self.assertEqual(MODULE._info_hash_source(values), "info")

    def test_does_not_treat_metainfo_dictionary_as_infohash(self):
        values = {b"info": {b"name": b"example.iso"}}
        self.assertEqual(MODULE._info_hash(values), "")
        self.assertEqual(MODULE._info_hash_source(values), "")

    def test_matches_orphan_info_fragment_by_piece_bitfield(self):
        have = b"\x81" * 16
        known = b"\x42" * 16
        identified = MODULE.TorrentRecord(
            0x1000,
            b"",
            {b"caption": b"example.iso", b"have": have},
        )
        orphan = MODULE.TorrentRecord(
            0x2000,
            b"",
            {b"info": bytes(range(20)), b"known": known},
            recovery_mode="Fragment",
        )
        self.assertEqual(
            MODULE._unique_bitfield_owner(
                orphan,
                {have: {"example.iso"}},
                {len(have): {"example.iso"}},
            ),
            "example.iso",
        )
        self.assertEqual(
            MODULE._unique_bitfield_owner(
                orphan,
                {},
                {len(have): {"example.iso", "same-sized.iso"}},
            ),
            "",
        )

    def test_correlated_fragment_confidence(self):
        record = MODULE.TorrentRecord(
            0x1000,
            b"",
            {
                b"caption": b"example.iso",
                b"path": b"C:\\Downloads\\example.iso",
                b"downloaded": 100,
                b"trackers": [b"https://tracker.example/announce"],
            },
            recovery_mode="CorrelatedFragments",
            fragment_count=2,
        )
        self.assertEqual(MODULE._confidence(record), "High")

    def test_parse_nested_resume_record(self):
        record = bdict(
            [
                (b"added_on", bint(1_700_000_000)),
                (b"caption", bstr(b"example")),
                (b"completed_on", bint(1_700_000_100)),
                (b"downloaded", bint(1234)),
                (b"path", bstr(b"C:\\Downloads")),
                (b"uploaded", bint(5678)),
            ]
        )
        payload = bdict([(b"example.torrent", record)])
        value, end = MODULE.BencodeParser(payload).parse()
        self.assertEqual(end, len(payload))
        self.assertEqual(value[b"example.torrent"][b"downloaded"], 1234)

    def test_carve_from_noisy_memory(self):
        record = bdict(
            [
                (b"caption", bstr(b"ubuntu.iso")),
                (b"downloaded", bint(4096)),
                (b"path", bstr(b"D:\\ISO")),
            ]
        )
        encoded = bdict([(b"ubuntu.torrent", record)])
        data = b"noise-d-not-bencode" + encoded + b"trailing"
        anchor = data.index(b"7:caption")
        records = MODULE.carve_records(data, anchor, 0x1000)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].name, b"ubuntu.torrent")
        self.assertEqual(records[0].values[b"caption"], b"ubuntu.iso")

    def test_rejects_truncated_value(self):
        with self.assertRaises(MODULE.BencodeError):
            MODULE.BencodeParser(b"d7:caption10:short").parse()

    def test_carves_fragment_without_outer_dictionary(self):
        fragment = b"noise" + b"".join(
            [
                bstr(b"path") + bstr(b"C:\\Downloads\\example.iso"),
                bstr(b"peers6") + bstr(bytes.fromhex("00000000000000000000ffffc0000201") + (6881).to_bytes(2, "big")),
                bstr(b"uploaded") + bint(42),
            ]
        ) + b"e"
        anchor = fragment.index(b"6:peers6")
        records = MODULE.carve_fragment_records(fragment, anchor, 0x2000)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].values[b"uploaded"], 42)
        self.assertEqual(records[0].values[b"path"], b"C:\\Downloads\\example.iso")

    def test_raw_little_endian_integer_fallback(self):
        raw = (1_700_000_000).to_bytes(8, "little")
        self.assertEqual(MODULE._integer(raw), 1_700_000_000)


if __name__ == "__main__":
    unittest.main()
