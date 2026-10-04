import importlib.util
import pathlib
import sys
import types
import unittest


PLUGIN = pathlib.Path(__file__).with_name("utorrentresume.py")
SPEC = importlib.util.spec_from_file_location(
    "volatility3.plugins.utorrentresume", PLUGIN
)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def bstr(value):
    return str(len(value)).encode() + b":" + value


def bint(value):
    return b"i" + str(value).encode() + b"e"


def bdict(items):
    return b"d" + b"".join(bstr(key) + value for key, value in items) + b"e"


class FakePhysicalLayer:
    minimum_address = 0

    def __init__(self, data, hit):
        self.data = data
        self.maximum_address = len(data) - 1
        self.hit = hit

    def scan(self, _context, _scanner, progress_callback=None, sections=None):
        yield self.hit, b"7:caption"

    def read(self, address, size, pad=False):
        return self.data[address : address + size].ljust(size, b"\x00")


class UtorrentMockIntegrationTests(unittest.TestCase):
    @staticmethod
    def _run_physical_records(records):
        fake_generator = types.SimpleNamespace(
            config={
                "max_results": 20,
                "physical_fallback": True,
                "scan_physical": False,
            },
            _selected_processes=lambda: [],
            _scan_physical=lambda: iter(records),
        )
        return list(MODULE.UtorrentResume._generator(fake_generator))

    def test_physical_fallback_emits_recovered_record(self):
        record = bdict(
            [
                (
                    b"sample.torrent",
                    bdict(
                        [
                            (b"caption", bstr(b"sample.iso")),
                            (b"downloaded", bint(8192)),
                            (b"path", bstr(b"D:\\Downloads")),
                        ]
                    ),
                )
            ]
        )
        data = bytearray(b"\x00" * 2048)
        record_start = 512
        data[record_start : record_start + len(record)] = record
        hit = record_start + record.index(b"7:caption")
        physical = FakePhysicalLayer(bytes(data), hit)
        kernel_layer = types.SimpleNamespace(config={"memory_layer": "physical"})
        context = types.SimpleNamespace(
            modules={"kernel": types.SimpleNamespace(layer_name="kernel_layer")},
            layers={"kernel_layer": kernel_layer, "physical": physical},
        )
        fake_scan = types.SimpleNamespace(
            config={"kernel": "kernel", "lookbehind": 256, "lookahead": 1024},
            context=context,
            _progress_callback=None,
        )
        recovered = list(MODULE.UtorrentResume._scan_physical(fake_scan))
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0][1].name, b"sample.torrent")

        fake_generator = types.SimpleNamespace(
            config={
                "max_results": 10,
                "physical_fallback": True,
                "scan_physical": False,
            },
            _selected_processes=lambda: [],
            _scan_physical=lambda: iter(recovered),
        )
        rows = list(MODULE.UtorrentResume._generator(fake_generator))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1][0], "PhysicalMemory")
        self.assertEqual(rows[0][1][1], -1)

    def test_correlates_two_torrents_by_unique_piece_vector_lengths(self):
        hash_a = bytes(range(20))
        hash_b = bytes(range(20, 40))
        records = [
            (
                0x1000,
                MODULE.TorrentRecord(
                    0x1000,
                    b"",
                    {b"caption": b"alpha.iso", b"have": b"\x01" * 16},
                    recovery_mode="Fragment",
                ),
            ),
            (
                0x2000,
                MODULE.TorrentRecord(
                    0x2000,
                    b"",
                    {b"caption": b"beta.iso", b"have": b"\x02" * 24},
                    recovery_mode="Fragment",
                ),
            ),
            (
                0x3000,
                MODULE.TorrentRecord(
                    0x3000,
                    b"",
                    {b"info": hash_a, b"known": b"\x11" * 16},
                    recovery_mode="Fragment",
                ),
            ),
            (
                0x4000,
                MODULE.TorrentRecord(
                    0x4000,
                    b"",
                    {b"info": hash_b, b"known": b"\x22" * 24},
                    recovery_mode="Fragment",
                ),
            ),
        ]
        rows = self._run_physical_records(records)
        self.assertEqual(len(rows), 2)
        recovered_hashes = {row[1][8] for row in rows}
        self.assertEqual(recovered_hashes, {hash_a.hex(), hash_b.hex()})

    def test_leaves_same_sized_multi_torrent_hash_fragment_unassigned(self):
        orphan_hash = bytes(range(20))
        records = [
            (
                0x1000,
                MODULE.TorrentRecord(
                    0x1000,
                    b"",
                    {b"caption": b"alpha.iso", b"have": b"\x01" * 16},
                    recovery_mode="Fragment",
                ),
            ),
            (
                0x2000,
                MODULE.TorrentRecord(
                    0x2000,
                    b"",
                    {b"caption": b"beta.iso", b"have": b"\x02" * 16},
                    recovery_mode="Fragment",
                ),
            ),
            (
                0x3000,
                MODULE.TorrentRecord(
                    0x3000,
                    b"",
                    {b"info": orphan_hash, b"known": b"\x11" * 16},
                    recovery_mode="Fragment",
                ),
            ),
        ]
        rows = self._run_physical_records(records)
        self.assertEqual(len(rows), 3)
        named_rows = [row for row in rows if row[1][6]]
        orphan_rows = [row for row in rows if not row[1][6]]
        self.assertEqual(len(named_rows), 2)
        self.assertTrue(all(not row[1][8] for row in named_rows))
        self.assertEqual(len(orphan_rows), 1)
        self.assertEqual(orphan_rows[0][1][8], orphan_hash.hex())


if __name__ == "__main__":
    unittest.main(verbosity=2)
