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


if __name__ == "__main__":
    unittest.main(verbosity=2)
