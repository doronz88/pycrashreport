import json
from pathlib import Path
from typing import Optional

import pytest
from apple_symbols import DeviceSupportSymbols, KernelSymbols
from apple_symbols.testing import build_fileset, build_macho
from symbolicator_server.client import SymbolicatorClient
from symbolicator_server.exceptions import ServerUnreachableError
from symbolicator_server.models import (
    FunctionSymbol,
    ImageInfo,
    Kernelcache,
    SharedCache,
)
from typer.testing import CliRunner

from pycrashreport import __main__ as cli
from pycrashreport import crash_report
from pycrashreport.crash_report import (
    KernelModeCrashReport,
    get_crash_report_from_buf,
)
from pycrashreport.symbols import (
    KernelSymbolChain,
    SymbolServerError,
    UserlandSymbolChain,
)
from tests.test_symbolication import (
    KERNEL_UUID,
    KERNEL_VMADDR,
    KEXT_UUID,
    KEXT_VMADDR,
    LIBFOO_UUID,
    LIBFOO_VMADDR,
    SHARED_CACHE_BASE,
    SHARED_CACHE_UUID,
    TEXT_EXEC,
    panic_report,
)

# Colors would split the messages the tests look for
RUNNER = CliRunner(env={"NO_COLOR": "1", "FORCE_COLOR": None, "TERM": "dumb"})

SERVER = "http://symbolicator.invalid"
KERNELCACHE_UUID = "2145355911C9E159EAAF481CD5EA4561"
KERNELCACHE_UUID_DASHED = "21453559-11c9-e159-eaaf-481cd5ea4561"
OTHER_KERNELCACHE_UUID = "136EF85E-1D94-2F7D-6168-1D2D94F042AF"
# The server keeps kernel addresses with bit 63 cleared
HIGH_BIT = 1 << 63


class FakeServer:
    """A server holding one build, of which it names `bar` and `panic` but neither `foo` nor the kext."""

    def find_dscs(self, device: str, build: str) -> list:
        if (device, build) != ("iPhone17,3", "23E246"):
            return []
        return [SharedCache(SHARED_CACHE_UUID.upper(), SHARED_CACHE_BASE)]

    def dsc_images(self, uuid: str) -> Optional[list]:
        if uuid.lower() != SHARED_CACHE_UUID:
            return None
        return [
            ImageInfo(
                LIBFOO_UUID.upper(),
                "/usr/lib/libfoo.dylib",
                LIBFOO_VMADDR,
                LIBFOO_VMADDR + 0x1000,
            )
        ]

    def find_kernelcaches(self, device: str, build: str) -> list:
        if (device, build) != ("iPhone17,3", "23E246"):
            return []
        return [
            # another kernelcache of the IPSW, which holds none of the images of the report
            Kernelcache(
                OTHER_KERNELCACHE_UUID, "kernelcache.research.iPhone17,3", None
            ),
            Kernelcache(
                KERNELCACHE_UUID_DASHED.upper(), "kernelcache.release.iPhone17,3", None
            ),
        ]

    def kernelcache_images(self, uuid: str) -> Optional[list]:
        if uuid.upper() == OTHER_KERNELCACHE_UUID:
            return [
                ImageInfo(
                    "0" * 8 + "-0000-0000-0000-" + "1" * 12,
                    "com.apple.kernel",
                    0,
                    0x1000,
                )
            ]
        if uuid.lower() == KERNEL_UUID:
            # known, but as an image and not as a kernelcache
            return []
        if uuid.lower() != KERNELCACHE_UUID_DASHED:
            return None
        return [
            ImageInfo(
                image_uuid.upper(),
                name,
                vmaddr + TEXT_EXEC - HIGH_BIT,
                vmaddr + TEXT_EXEC + 0x1000 - HIGH_BIT,
            )
            for image_uuid, name, vmaddr in (
                (KERNEL_UUID, "com.apple.kernel", KERNEL_VMADDR),
                (KEXT_UUID, "com.apple.driver.Foo", KEXT_VMADDR),
            )
        ]

    def image_symbols(
        self, uuid: str, dsc: Optional[str] = None, kernelcache: Optional[str] = None
    ) -> Optional[list]:
        if uuid.lower() == LIBFOO_UUID:
            return [
                FunctionSymbol(LIBFOO_VMADDR + 0x100, LIBFOO_VMADDR + 0x200, None),
                FunctionSymbol(
                    LIBFOO_VMADDR + 0x200, LIBFOO_VMADDR + 0x300, "_remote_bar"
                ),
            ]
        if uuid.lower() == KERNEL_UUID:
            start = KERNEL_VMADDR + TEXT_EXEC - HIGH_BIT
            return [FunctionSymbol(start + 0x100, start + 0x200, "_remote_panic")]
        if uuid.lower() == KEXT_UUID:
            start = KEXT_VMADDR + TEXT_EXEC - HIGH_BIT
            return [FunctionSymbol(start + 0x100, start + 0x200, None)]
        return None


@pytest.fixture(autouse=True)
def server(monkeypatch: pytest.MonkeyPatch) -> list:
    """Answer for the server at `SERVER`, and list the URLs which got connected to."""
    connected = []
    fake = FakeServer()

    def connect(url: str) -> SymbolicatorClient:
        connected.append(url)
        if url != SERVER:
            raise ServerUnreachableError(url, "no such host")
        client = SymbolicatorClient(url)
        for name in (
            "find_dscs",
            "dsc_images",
            "find_kernelcaches",
            "kernelcache_images",
            "image_symbols",
        ):
            monkeypatch.setattr(client, name, getattr(fake, name))
        return client

    monkeypatch.setattr(SymbolicatorClient, "connect", connect)
    return connected


def build_symbols(root: Path, names: dict) -> DeviceSupportSymbols:
    (root / "Symbols/usr/lib").mkdir(parents=True)
    (root / "Symbols/usr/lib/libfoo.dylib").write_bytes(
        build_macho(LIBFOO_UUID, LIBFOO_VMADDR, 0x1000, names, [0x100, 0x200, 0x300])
    )
    return DeviceSupportSymbols.load(root / "Symbols", root / "index")


@pytest.fixture
def symbols(tmp_path: Path) -> DeviceSupportSymbols:
    return build_symbols(tmp_path / "local", {"_foo": 0x100, "_bar": 0x200})


@pytest.fixture
def kernel_symbols(tmp_path: Path) -> KernelSymbols:
    kernelcache = tmp_path / "kernelcache.decompressed"
    kernelcache.write_bytes(
        build_fileset(
            [
                (
                    name,
                    {
                        "image_uuid": image_uuid,
                        "vmaddr": vmaddr,
                        "vmsize": 0x10000,
                        "symbols": {symbol: TEXT_EXEC + 0x100},
                        "functions": [TEXT_EXEC + 0x100, TEXT_EXEC + 0x300],
                        "text_exec": TEXT_EXEC,
                    },
                )
                for name, image_uuid, vmaddr, symbol in (
                    ("com.apple.kernel", KERNEL_UUID, KERNEL_VMADDR, "_panic"),
                    ("com.apple.driver.Foo", KEXT_UUID, KEXT_VMADDR, "_Foo_start"),
                )
            ]
        )
    )
    return KernelSymbols.load(kernelcache, index_dir=tmp_path / "kernel_index")


def panic_buf(kernelcache_uuid: Optional[str] = KERNELCACHE_UUID) -> str:
    """A panic which tells the kernelcache of its device, as the panics of a device do."""
    payload = dict(panic_report()._data)
    if kernelcache_uuid is not None:
        payload["panicString"] += f"\nFileset Kernelcache UUID: {kernelcache_uuid}"
    return (
        json.dumps({"bug_type": "210", "timestamp": "2026-11-16 17:35:06.00 +0200"})
        + "\n"
        + json.dumps(payload)
    )


def panic(
    kernelcache_uuid: Optional[str] = KERNELCACHE_UUID, server: Optional[str] = SERVER
) -> KernelModeCrashReport:
    report = get_crash_report_from_buf(
        panic_buf(kernelcache_uuid), filename="panic-full.ips"
    )
    assert isinstance(report, KernelModeCrashReport)
    if server is not None:
        report.symbol_server = server
    return report


def named(frames: list) -> list:
    return [(frame.image, frame.symbol, frame.symbol_offset) for frame in frames]


def test_chain_asks_the_next_source_for_what_the_first_does_not_name(
    tmp_path: Path, symbols: DeviceSupportSymbols
):
    first = build_symbols(tmp_path / "first", {"_first_bar": 0x200})
    chain = UserlandSymbolChain([first, symbols])
    image = chain.image_by_uuid(LIBFOO_UUID)
    assert image is not None
    assert chain.shared_cache_base == SHARED_CACHE_BASE
    assert chain.image_by_address(LIBFOO_VMADDR + 0x210) == image
    assert chain.symbolicate(image, LIBFOO_VMADDR + 0x210) == ("first_bar", 0x10)
    assert chain.symbolicate(image, LIBFOO_VMADDR + 0x110) == ("foo", 0x10)
    # in the function at 0x300, which neither names
    assert chain.symbolicate(image, LIBFOO_VMADDR + 0x310) is None


def test_panic_tells_its_kernelcache():
    assert panic().kernelcache_uuid == KERNELCACHE_UUID_DASHED
    assert panic(None).kernelcache_uuid is None


def test_server_names_frames_without_symbols_on_the_host(caplog):
    report = panic()
    assert named(report.panicked_thread_frames[:5]) == [
        ("com.apple.kernel", "_remote_panic", 0x10),
        ("com.apple.driver.Foo", None, None),
        ("com.apple.kernel", None, None),
        ("libfoo.dylib", "remote_bar", 0x10),
        # a return address at the start of `bar` belongs to `foo`, which the server does not name
        ("libfoo.dylib", None, None),
    ]
    assert caplog.messages == []


def test_reports_ask_the_server_of_the_environment(monkeypatch, server: list):
    monkeypatch.setenv(crash_report.SERVER_ENVVAR, SERVER)
    report = panic(server=None)
    assert report.symbol_server == SERVER
    # nothing is asked before frames are read
    assert server == []
    assert named(report.panicked_thread_frames[3:4]) == [
        ("libfoo.dylib", "remote_bar", 0x10)
    ]
    assert server == [SERVER]


def test_reports_ask_no_server_unless_given_one(server: list):
    report = panic(server=None)
    assert report.symbol_server is None
    assert named(report.panicked_thread_frames[3:4]) == [
        (SHARED_CACHE_UUID, None, None)
    ]
    assert server == []


def test_host_symbols_name_what_the_server_does_not(
    symbols: DeviceSupportSymbols, kernel_symbols: KernelSymbols
):
    report = panic()
    report.device_support_symbols = symbols
    report.kernel_symbols = kernel_symbols
    assert named(report.panicked_thread_frames[:5]) == [
        ("com.apple.kernel", "_remote_panic", 0x10),
        ("com.apple.driver.Foo", "Foo_start", 0x80),
        ("com.apple.kernel", None, None),
        ("libfoo.dylib", "remote_bar", 0x10),
        ("libfoo.dylib", "foo", 0x100),
    ]
    assert isinstance(report._userland_symbols, UserlandSymbolChain)
    assert isinstance(report._kernel_symbol_source, KernelSymbolChain)


def test_host_symbols_name_a_build_the_server_does_not_hold(
    symbols: DeviceSupportSymbols, kernel_symbols: KernelSymbols, caplog
):
    report = panic("00000000000000000000000000000000")
    report._data["build"] = "iPhone OS 26.5 (23F77)"
    report.device_support_symbols = symbols
    report.kernel_symbols = kernel_symbols
    assert named(report.panicked_thread_frames[:5]) == [
        ("com.apple.kernel", "panic", 0x10),
        ("com.apple.driver.Foo", "Foo_start", 0x80),
        ("com.apple.kernel", None, None),
        ("libfoo.dylib", "bar", 0x10),
        ("libfoo.dylib", "foo", 0x100),
    ]
    assert report._userland_symbols is symbols
    assert report._kernel_symbol_source is kernel_symbols
    assert sorted(caplog.messages) == [
        f"{SERVER} does not hold the kernelcache 00000000-0000-0000-0000-000000000000, "
        f"scan its IPSW to name kernel frames with it",
        f"{SERVER} holds no symbols of iPhone17,3 (23F77), scan its IPSW to name user frames with it",
    ]


def test_server_does_not_take_another_image_for_a_kernelcache(
    kernel_symbols: KernelSymbols, caplog
):
    report = panic(KERNEL_UUID.replace("-", ""))
    report.kernel_symbols = kernel_symbols
    assert report._kernel_symbol_source is kernel_symbols
    assert [KERNEL_UUID in message for message in caplog.messages] == [True]


def test_server_finds_the_kernelcache_of_a_report_which_does_not_tell_it(caplog):
    # as a stackshot, which tells its device, its build and its kernel images only
    report = panic(None)
    assert report.kernelcache_uuid is None
    assert named(report.panicked_thread_frames[:1]) == [
        ("com.apple.kernel", "_remote_panic", 0x10)
    ]
    assert caplog.messages == []


def test_server_tells_a_report_whose_kernelcache_it_does_not_hold(
    monkeypatch: pytest.MonkeyPatch, caplog
):
    monkeypatch.setattr(FakeServer, "find_kernelcaches", lambda self, device, build: [])
    report = panic(None)
    assert named(report.panicked_thread_frames[:1]) == [("kernel", None, None)]
    assert named(report.panicked_thread_frames[3:4]) == [
        ("libfoo.dylib", "remote_bar", 0x10)
    ]
    assert caplog.messages == [
        f"{SERVER} holds no kernelcache of iPhone17,3 (23E246) with the kernel images of "
        f"the report, scan its IPSW to name kernel frames with it"
    ]


def test_server_which_cannot_be_reached_fails_reading_frames():
    report = panic(server="http://other.invalid")
    with pytest.raises(SymbolServerError, match="Reaching http://other.invalid failed"):
        _ = report.panicked_thread_frames


@pytest.fixture
def panic_file(tmp_path: Path) -> Path:
    file = tmp_path / "panic-full.ips"
    file.write_text(panic_buf())
    return file


def test_cli_names_frames_given_a_server(panic_file: Path, server: list):
    result = RUNNER.invoke(cli.app, [str(panic_file), "--server", SERVER])
    assert result.exit_code == 0, result.output
    assert server == [SERVER]
    assert "(_remote_panic + 0x10)" in result.output
    assert "(remote_bar + 0x10)" in result.output


def test_cli_takes_the_server_from_the_environment(panic_file: Path, server: list):
    result = RUNNER.invoke(
        cli.app, [str(panic_file)], env={crash_report.SERVER_ENVVAR: SERVER}
    )
    assert result.exit_code == 0, result.output
    assert server == [SERVER]
    assert "(remote_bar + 0x10)" in result.output


def test_cli_does_not_ask_a_server_unless_given_one(panic_file: Path, server: list):
    result = RUNNER.invoke(cli.app, [str(panic_file)])
    assert result.exit_code == 0, result.output
    assert server == []
    assert "remote_bar" not in result.output


def test_cli_tells_a_server_it_cannot_reach(panic_file: Path):
    result = RUNNER.invoke(
        cli.app, [str(panic_file), "--server", "http://other.invalid"]
    )
    assert result.exit_code != 0
    assert "Reaching http://other.invalid failed: no such host" in " ".join(
        result.output.split()
    )
