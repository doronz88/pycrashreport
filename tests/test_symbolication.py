import json
from pathlib import Path

import pytest
from apple_symbols import DeviceSupportSymbols, KernelSymbols
from apple_symbols.testing import build_fileset, build_macho
from typer.testing import CliRunner

from pycrashreport import crash_report
from pycrashreport.__main__ import app
from pycrashreport.crash_report import (
    KernelModeCrashReport,
    PanicFrame,
    get_crash_report_from_buf,
    parse_report,
)

# Colors would split the messages the tests look for
RUNNER = CliRunner(env={"NO_COLOR": "1", "FORCE_COLOR": None, "TERM": "dumb"})

REPORTS = Path(__file__).parent

SHARED_CACHE_BASE = 0x180000000
SHARED_CACHE_UUID = "5c5c5c5c-0000-1111-2222-333333333333"
LIBFOO_UUID = "11111111-2222-3333-4444-555555555555"
LIBFOO_VMADDR = SHARED_CACHE_BASE + 0x10000
DAEMON_UUID = "99999999-8888-7777-6666-555555555555"
KERNEL_UUID = "12121212-3434-5656-7878-909090909090"
KEXT_UUID = "abababab-cdcd-efef-0101-232323232323"
KERNEL_VMADDR = 0xFFFFFE0007004000
KEXT_VMADDR = 0xFFFFFE0007100000
# Offset of `__TEXT_EXEC` from `__TEXT` in the kernel images
TEXT_EXEC = 0x4000
KERNEL_SLIDE = 0x1000000
SHARED_CACHE_SLIDE = 0x2000000
# The executable of the faulting process in the monterey report, which the report leaves unnamed
SLEEP_UUID = "b9252db9-9910-3b36-865a-01e20427c7e0"

PANIC_TEXT = "\n".join(
    [
        "panic(cpu 1 caller 0xfffffe0008123456): something broke",
        "Debugger message: panic",
        f"Kernel UUID: {KERNEL_UUID.upper()}",
        "Panicked task 0xfffffe2eb5d78000: 100 pages, 2 threads: pid 77: food",
        "Panicked thread: 0xfffffe2eb5d78bf0, backtrace: 0xfffffe4b69f23e50, tid: 500",
    ]
)


@pytest.fixture
def symbols(tmp_path: Path) -> DeviceSupportSymbols:
    root = tmp_path / "Symbols"
    (root / "usr/lib").mkdir(parents=True)
    (root / "usr/lib/libfoo.dylib").write_bytes(
        build_macho(
            LIBFOO_UUID,
            LIBFOO_VMADDR,
            0x1000,
            {"_foo": 0x100, "_bar": 0x200},
            [0x100, 0x200, 0x300],
        )
    )
    return DeviceSupportSymbols.load(root, tmp_path / "index")


@pytest.fixture
def kernel_symbols(tmp_path: Path) -> KernelSymbols:
    kernelcache = tmp_path / "kernelcache.decompressed"
    kernelcache.write_bytes(
        build_fileset(
            [
                (
                    "com.apple.kernel",
                    {
                        "image_uuid": KERNEL_UUID,
                        "vmaddr": KERNEL_VMADDR,
                        "vmsize": 0x10000,
                        "symbols": {"_panic": TEXT_EXEC + 0x100},
                        "functions": [TEXT_EXEC + 0x100, TEXT_EXEC + 0x300],
                        "text_exec": TEXT_EXEC,
                    },
                ),
                (
                    "com.apple.driver.Foo",
                    {
                        "image_uuid": KEXT_UUID,
                        "vmaddr": KEXT_VMADDR,
                        "vmsize": 0x10000,
                        "symbols": {"_Foo_start": TEXT_EXEC + 0x100},
                        "functions": [TEXT_EXEC + 0x100],
                        "text_exec": TEXT_EXEC,
                    },
                ),
            ]
        )
    )
    return KernelSymbols.load(kernelcache, index_dir=tmp_path / "kernel_index")


def panic_report() -> KernelModeCrashReport:
    """A panic whose panicked thread went through every kind of image a report locates frames with."""
    payload = {
        "product": "iPhone17,3",
        "build": "iPhone OS 26.4 (23E246)",
        "panicString": PANIC_TEXT,
        "binaryImages": [
            [KERNEL_UUID, KERNEL_VMADDR + TEXT_EXEC + KERNEL_SLIDE, "T"],
            [KEXT_UUID, KEXT_VMADDR + TEXT_EXEC + KERNEL_SLIDE, "T"],
            ["00000000-0000-0000-0000-000000000000", 0, "A"],
            [SHARED_CACHE_UUID, SHARED_CACHE_BASE + SHARED_CACHE_SLIDE, "S"],
            [LIBFOO_UUID, LIBFOO_VMADDR + SHARED_CACHE_SLIDE, "C"],
            [DAEMON_UUID, 0x104000000, "P"],
        ],
        "processByPid": {
            "0": {
                "procname": "kernel_task",
                "threadById": {"1": {"kernelFrames": [[1, 0x180]]}},
            },
            "77": {
                "procname": "food",
                "threadById": {
                    "500": {
                        "name": "worker",
                        "kernelFrames": [[0, 0x110], [1, 0x180], [0, 0x310], [2, 0]],
                        "userFrames": [
                            [3, 0x10210],
                            [4, 0x200],
                            [5, 0x40],
                            [2, 0x7FFF0000],
                        ],
                    },
                    "501": {"userFrames": [[4, 0x104]]},
                },
            },
        },
    }
    report = get_crash_report_from_buf(
        json.dumps(
            {
                "bug_type": "210",
                "timestamp": "2026-11-16 17:35:06.00 +0200",
                "incident_id": "ID",
            }
        )
        + "\n"
        + json.dumps(payload),
        filename="panic-full.ips",
    )
    assert isinstance(report, KernelModeCrashReport)
    return report


def test_panic_tells_its_device_and_build():
    report = panic_report()
    assert report.product_type == "iPhone17,3"
    assert report.build_version == "23E246"

    fixture = parse_report(
        REPORTS / "kernel_mode_crash_report_ios16_forceReset-full.ips"
    )
    assert fixture.product_type == "iPhone11,8"
    assert fixture.build_version == "20C65"


def test_panic_frames_without_symbols():
    report = panic_report()
    assert report.device_support_symbols is None

    assert report.panicked_thread_frames == [
        # the panic text names the kernel
        PanicFrame(
            KERNEL_VMADDR + TEXT_EXEC + KERNEL_SLIDE + 0x110, True, "kernel", 0x110
        ),
        PanicFrame(
            KEXT_VMADDR + TEXT_EXEC + KERNEL_SLIDE + 0x180, True, KEXT_UUID, 0x180
        ),
        PanicFrame(
            KERNEL_VMADDR + TEXT_EXEC + KERNEL_SLIDE + 0x310, True, "kernel", 0x310
        ),
        PanicFrame(
            SHARED_CACHE_BASE + SHARED_CACHE_SLIDE + 0x10210,
            False,
            SHARED_CACHE_UUID,
            0x10210,
        ),
        PanicFrame(
            LIBFOO_VMADDR + SHARED_CACHE_SLIDE + 0x200, False, LIBFOO_UUID, 0x200
        ),
        PanicFrame(0x104000040, False, DAEMON_UUID, 0x40),
        # an address no image contains
        PanicFrame(0x7FFF0000, False),
    ]
    rendered = report.__rich__().plain
    assert "Panicked thread backtrace:" in rendered
    assert (
        f"kernel [{KEXT_UUID}] 0x{KEXT_VMADDR + TEXT_EXEC + KERNEL_SLIDE + 0x180:x} (+ 0x180)"
        in rendered
    )
    assert "Kernel frames are named given the kernelcache the device ran." in rendered
    assert (
        "User frames are named given the Xcode DeviceSupport of iPhone17,3 (23E246)."
        in rendered
    )


def test_panic_user_frames_are_named_by_device_support_alone(
    symbols: DeviceSupportSymbols,
):
    report = panic_report()
    report.device_support_symbols = symbols

    frames = report.panicked_thread_frames
    assert [
        (frame.image, frame.symbol, frame.symbol_offset) for frame in frames[:3]
    ] == [
        ("kernel", None, None),
        (KEXT_UUID, None, None),
        ("kernel", None, None),
    ]
    assert [
        (frame.image, frame.image_offset, frame.symbol, frame.symbol_offset)
        for frame in frames[3:]
    ] == [
        # found by its offset in the whole shared cache
        ("libfoo.dylib", 0x210, "bar", 0x10),
        # found by the UUID of the library; a return address at the start of `bar` belongs to `foo`
        ("libfoo.dylib", 0x200, "foo", 0x100),
        # the symbols do not hold the executables of processes
        (DAEMON_UUID, 0x40, None, None),
        (None, None, None, None),
    ]
    rendered = report.__rich__().plain
    assert (
        f"user   [libfoo.dylib] 0x{SHARED_CACHE_BASE + SHARED_CACHE_SLIDE + 0x10210:x} (bar + 0x10)"
        in rendered
    )
    assert "Kernel frames are named given the kernelcache the device ran." in rendered
    assert "User frames are named" not in rendered


def test_panic_kernel_frames_are_named_by_a_kernelcache(kernel_symbols: KernelSymbols):
    report = panic_report()
    report.kernel_symbols = kernel_symbols

    frames = report.panicked_thread_frames
    assert [
        (frame.image, frame.symbol, frame.symbol_offset) for frame in frames[:3]
    ] == [
        ("com.apple.kernel", "panic", 0x10),
        ("com.apple.driver.Foo", "Foo_start", 0x80),
        # in the function at 0x300, which has no symbol
        ("com.apple.kernel", None, None),
    ]
    assert "Kernel frames are named" not in report.__rich__().plain


def test_panic_tells_a_kernelcache_holds_no_symbols(tmp_path: Path):
    kernelcache = tmp_path / "kernelcache.decompressed"
    kernelcache.write_bytes(
        build_fileset(
            [
                (
                    "com.apple.kernel",
                    {
                        "image_uuid": KERNEL_UUID,
                        "vmaddr": KERNEL_VMADDR,
                        "vmsize": 0x10000,
                        "symbols": {},
                        "functions": [TEXT_EXEC + 0x100],
                        "text_exec": TEXT_EXEC,
                    },
                )
            ]
        )
    )
    report = panic_report()
    report.kernel_symbols = KernelSymbols.load(
        kernelcache, index_dir=tmp_path / "index"
    )

    assert report.panicked_thread_frames[0].image == "com.apple.kernel"
    assert report.panicked_thread_frames[0].symbol is None
    assert "The kernelcache holds no symbols" in report.__rich__().plain


def test_panic_processes(symbols: DeviceSupportSymbols):
    report = panic_report()
    report.device_support_symbols = symbols

    kernel_task, food = report.processes
    assert (kernel_task.pid, kernel_task.name) == (0, "kernel_task")
    assert (food.pid, food.name) == (77, "food")
    assert [(thread.tid, thread.name) for thread in food.threads] == [
        (500, "worker"),
        (501, None),
    ]
    # the innermost frame is where the thread is, not where it returns to
    assert (
        food.threads[1].frames[0].symbol,
        food.threads[1].frames[0].symbol_offset,
    ) == ("foo", 4)


def test_panic_without_the_panicked_thread():
    report = parse_report(
        REPORTS / "kernel_mode_crash_report_ios16_forceReset-full.ips"
    )
    assert [frame.image for frame in report.panicked_thread_frames[:3]] == [
        "kernel",
        "kernel",
        "com.apple.driver.AppleM68Buttons",
    ]

    text_only = get_crash_report_from_buf(
        json.dumps({"bug_type": "210", "timestamp": "2026-11-16 17:35:06.00 +0200"})
        + "\n"
        + PANIC_TEXT
    )
    assert text_only.processes == []
    assert text_only.panicked_thread_frames == []
    assert "Panicked thread backtrace" not in text_only.__rich__().plain


def test_device_support_is_looked_up_by_device_and_build(
    monkeypatch, symbols: DeviceSupportSymbols
):
    lookups = []

    def find(product_type, build_version):
        lookups.append((product_type, build_version))
        return symbols.root

    monkeypatch.setattr(crash_report, "find_device_support_symbols", find)
    report = panic_report()
    assert report.device_support_symbols.root == symbols.root
    assert lookups == [("iPhone17,3", "23E246")]
    assert report.panicked_thread_frames[3].symbol == "bar"


def test_user_mode_frames_the_device_left_unnamed(tmp_path: Path):
    root = tmp_path / "Symbols"
    (root / "bin").mkdir(parents=True)
    (root / "bin/sleep").write_bytes(
        build_macho(SLEEP_UUID, 0x100000000, 0x8000, {"_main": 0x3D00}, [0x3D00])
    )
    symbols = DeviceSupportSymbols.load(root, tmp_path / "index")
    path = REPORTS / "user_mode_crash_report_monterey_non_symbolicated.ips"
    unnamed = parse_report(path)
    assert (unnamed.product_type, unnamed.build_version) == ("MacBookPro15,1", "21C52")
    assert [frame.symbol for frame in unnamed.frames] == [
        None,
        "nanosleep",
        None,
        "start",
    ]

    report = parse_report(path)
    report.device_support_symbols = symbols
    assert [(frame.symbol, frame.symbol_offset) for frame in report.frames] == [
        (None, None),
        # what the device named stays as it named it
        ("nanosleep", 196),
        ("main", 15826 - 0x3D00),
        ("start", 462),
    ]


def test_cli_names_kernel_frames_given_a_kernelcache(
    tmp_path: Path, kernel_symbols: KernelSymbols, monkeypatch
):
    report_file = tmp_path / "panic-full.ips"
    report_file.write_text(
        json.dumps({"bug_type": "210", "timestamp": "2026-11-16 17:35:06.00 +0200"})
        + "\n"
        + json.dumps(panic_report()._data)
    )
    loaded = []

    def load(kernelcache, signatures=None):
        loaded.append((kernelcache, signatures))
        return kernel_symbols

    monkeypatch.setattr(KernelSymbols, "load", load)
    result = RUNNER.invoke(
        app,
        [
            str(report_file),
            "--kernelcache",
            str(tmp_path / "kc"),
            "--kernel-signatures",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert loaded == [(tmp_path / "kc", tmp_path)]
    assert "[com.apple.driver.Foo]" in result.output
    assert "(Foo_start + 0x80)" in result.output


def test_cli_rejects_signatures_without_a_kernelcache(tmp_path: Path):
    result = RUNNER.invoke(
        app,
        [
            str(REPORTS / "kernel_mode_crash_report_ios16_forceReset-full.ips"),
            "--kernel-signatures",
            str(tmp_path),
        ],
    )
    assert result.exit_code != 0
    assert "--kernel-signatures requires --kernelcache" in result.output


@pytest.fixture
def panic_file(tmp_path: Path) -> Path:
    report_file = tmp_path / "panic-full.ips"
    report_file.write_text(
        json.dumps({"bug_type": "210", "timestamp": "2026-11-16 17:35:06.00 +0200"})
        + "\n"
        + json.dumps(panic_report()._data)
    )
    return report_file


def test_cli_lists_the_threads_of_the_processes_asked_for(panic_file: Path):
    result = RUNNER.invoke(app, [str(panic_file)])
    assert result.exit_code == 0, result.output
    assert "Process:" not in result.output

    result = RUNNER.invoke(app, [str(panic_file), "-p", "food"])
    assert result.exit_code == 0, result.output
    assert "Process: food (pid 77, " in result.output
    assert "Thread: tid 500 worker (panicked)" in result.output
    assert "Process: kernel_task" not in result.output

    # by pid, and asking twice for a process lists it once
    result = RUNNER.invoke(
        app, [str(panic_file), "-p", "0", "--process", "food", "-p", "77"]
    )
    assert result.exit_code == 0, result.output
    assert "Process: kernel_task (pid 0, 1 threads)" in result.output
    assert result.output.count("Process: food") == 1


def test_cli_lists_the_threads_of_every_process(panic_file: Path):
    result = RUNNER.invoke(app, [str(panic_file), "--all"])
    assert result.exit_code == 0, result.output
    assert "Process: kernel_task (pid 0, 1 threads)" in result.output
    assert "Process: food (pid 77, " in result.output
    assert (
        f"kernel [{KEXT_UUID}] 0x{KEXT_VMADDR + TEXT_EXEC + KERNEL_SLIDE + 0x180:x} (+ 0x180)"
        in result.output
    )


def test_cli_rejects_a_process_the_report_does_not_hold(panic_file: Path):
    result = RUNNER.invoke(app, [str(panic_file), "-p", "nosuchd"])
    assert result.exit_code == 2
    assert "holds no process nosuchd" in result.output


def test_cli_rejects_processes_of_a_report_which_is_not_a_panic():
    result = RUNNER.invoke(
        app,
        [
            str(REPORTS / "user_mode_crash_report_monterey_non_symbolicated.ips"),
            "--all",
        ],
    )
    assert result.exit_code == 2
    assert "apply to panic reports only" in result.output
