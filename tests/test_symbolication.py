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
    SpindumpCrashReport,
    StackshotCrashReport,
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


def exception_panic_text(pc: int, lr: int) -> str:
    """A panic over an exception, which the kernel prints the registers of after its first line."""
    registers = [f"x{i}" for i in range(29)] + [
        "fp",
        "lr",
        "sp",
        "pc",
        "cpsr",
        "esr",
        "far",
    ]
    values = {
        "x0": 0,
        "x1": 0x10,
        "lr": lr,
        "sp": 0xFFFFFFE8156A3690,
        "pc": pc,
        "cpsr": 0x60400204,
        "esr": 0x96000006,
        "far": 0x10,
    }
    rows = [
        "\t  "
        + " ".join(
            f"{name + ':':<4} 0x{values.get(name, 0xFFFFFFE4CCB3A000 + i + j):016x}"
            for j, name in enumerate(registers[i : i + 4])
        )
        for i in range(0, len(registers), 4)
    ]
    first, *rest = PANIC_TEXT.splitlines()
    first = first.replace(
        "something broke",
        f"Kernel data abort. at pc 0x{pc:016x}, lr 0x{lr:016x} "
        f"(saved state: 0xffffffe8156a3340)",
    )
    return "\n".join([first, *rows, *rest])


def panic_report(panic_text: str = PANIC_TEXT) -> KernelModeCrashReport:
    """A panic whose panicked thread went through every kind of image a report locates frames with."""
    payload = {
        "product": "iPhone17,3",
        "build": "iPhone OS 26.4 (23E246)",
        "panicString": panic_text,
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


def test_panic_over_an_exception_tells_its_registers(kernel_symbols: KernelSymbols):
    pc = KERNEL_VMADDR + TEXT_EXEC + KERNEL_SLIDE + 0x110
    lr = KEXT_VMADDR + TEXT_EXEC + KERNEL_SLIDE + 0x180
    report = panic_report(exception_panic_text(pc, lr))
    report.kernel_symbols = kernel_symbols

    assert report.panic_string.startswith("Kernel data abort. at pc ")
    assert [register.name for register in report.registers] == [
        *(f"x{i}" for i in range(29)),
        "fp",
        "lr",
        "sp",
        "pc",
        "cpsr",
        "esr",
        "far",
    ]
    registers = {register.name: register.value for register in report.registers}
    assert (registers["pc"], registers["lr"]) == (pc, lr)
    assert (registers["esr"], registers["far"]) == (0x96000006, 0x10)
    # what follows the registers is still read
    assert report.debugger_message == "panic"
    assert report.panicked_task is not None

    assert [
        (name, frame.image, frame.symbol, frame.symbol_offset)
        for name, frame in report.register_frames
    ] == [
        ("pc", "com.apple.kernel", "panic", 0x10),
        # `lr` is an address to return to, as a frame which called another is
        ("lr", "com.apple.driver.Foo", "Foo_start", 0x80),
    ]
    text = report.__rich__().plain
    assert f"pc = 0x{pc:016x}" in text
    assert f"[com.apple.kernel] 0x{pc:x} (panic + 0x10)" in text


def test_panic_registers_point_nowhere_without_symbols():
    pc = KERNEL_VMADDR + TEXT_EXEC + KERNEL_SLIDE + 0x110
    report = panic_report(exception_panic_text(pc, 0))
    assert len(report.registers) == 36
    assert report.register_frames == []
    assert f"pc = 0x{pc:016x}" in report.__rich__().plain


def test_panic_which_is_not_over_an_exception_has_no_registers():
    report = panic_report()
    assert report.registers == []
    assert "Registers:" not in report.__rich__().plain


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


def test_cli_lists_the_threads_of_a_crash():
    crash = str(REPORTS / "user_mode_crash_report_monterey_non_symbolicated.ips")
    result = RUNNER.invoke(app, [crash, "--all"])
    assert result.exit_code == 0, result.output
    assert (
        "Thread: 0, tid 135513, queue com.apple.main-thread (crashed)" in result.output
    )

    # a crash is of one process
    result = RUNNER.invoke(app, [crash, "-p", "sleep"])
    assert result.exit_code == 2
    assert "--process and --running apply to" in result.output


def test_cli_rejects_processes_of_a_report_without_any(tmp_path: Path):
    report_file = tmp_path / "JetsamEvent.ips"
    report_file.write_text(
        json.dumps({"bug_type": "298", "timestamp": "2026-11-16 17:35:06.00 +0200"})
        + "\nanything"
    )
    result = RUNNER.invoke(app, [str(report_file), "--all"])
    assert result.exit_code == 2
    assert "--process, --all and --running apply to" in result.output


UNSLID_KERNELCACHE_BASE = 0xFFFFFE0000000000
EXCLAVE_UUID = "77777777-0000-1111-2222-333333333333"
DRIVERKIT_CACHE_UUID = "d4d4d4d4-0000-1111-2222-333333333333"


def stackshot_report() -> StackshotCrashReport:
    """A stackshot, which locates kernel frames by their unslid address in the kernelcache."""

    def kernel_offset(address: int) -> int:
        return address - UNSLID_KERNELCACHE_BASE

    payload = {
        "product": "iPhone19,4",
        "build": "iPhone OS 27.2.1 (24B91034)",
        "kernel": "Darwin Kernel Version 27.2.0",
        "reason": "stackshot via sysdiagnose",
        "notes": ["Requested by sysdiagnose_helper"],
        "frontmostPids": [77],
        "memoryStatus": {"pageSize": 16384, "memoryPages": {"active": 5, "free": 7}},
        "binaryImages": [
            ["cdcdcdcd-0000-1111-2222-333333333333", UNSLID_KERNELCACHE_BASE, "U"],
            ["00000000-0000-0000-0000-000000000000", 0, "A"],
            [SHARED_CACHE_UUID, SHARED_CACHE_BASE, "S"],
            [EXCLAVE_UUID, 0x7FFC000, "P"],
            [DRIVERKIT_CACHE_UUID, SHARED_CACHE_BASE, "S"],
        ],
        "processByPid": {
            "0": {
                "procname": "kernel_task",
                "threadById": {
                    "1": {
                        "name": "idle #0",
                        "state": ["TH_RUN", "TH_IDLE"],
                        "basePriority": 0,
                        "schedPriority": 0,
                        "user_usec": 0,
                        "system_usec": 9,
                        "kernelFrames": [
                            [0, kernel_offset(KERNEL_VMADDR + TEXT_EXEC + 0x110)],
                            [3, 0x40],
                            [0, kernel_offset(KEXT_VMADDR + TEXT_EXEC + 0x180)],
                        ],
                    }
                },
            },
            "77": {
                "procname": "food",
                "flags": ["foreground", "sharedRegionSystem"],
                "frontmost": 1,
                "parentPid": 1,
                "userID": 501,
                "groupID": 501,
                "residentMemoryBytes": 4096,
                "userTimeTask": 1.5,
                "systemTimeTask": 0.5,
                "processUptime": 282.0,
                "csFlags": 570434305,
                "waitInfo": ["thread 500: mach_msg receive on port set 0x1"],
                "threadById": {
                    "500": {
                        "state": ["TH_WAIT"],
                        "dispatch_queue_label": "com.food.queue",
                        "qosEffective": "QOS_CLASS_USER_INITIATED",
                        "snapshotFlags": ["kUser64_p"],
                        "lastRunTime": 0.99,
                        "basePriority": 31,
                        "schedPriority": 47,
                        "user_usec": 3,
                        "system_usec": 4,
                        "kernelFrames": [[1, 0]],
                        "userFrames": [[2, 0x10104]],
                    },
                },
            },
            "90": {
                "procname": "dext",
                "flags": ["sharedRegionOther"],
                "threadById": {"600": {"userFrames": [[4, 0x10104]]}},
            },
        },
    }
    report = get_crash_report_from_buf(
        json.dumps(
            {
                "bug_type": "288",
                "timestamp": "2026-11-17 04:24:10.00 -0800",
                "incident_id": "ID",
            }
        )
        + "\n"
        + json.dumps(payload),
        filename="stacks.ips",
    )
    assert isinstance(report, StackshotCrashReport)
    return report


def test_stackshot_summary():
    report = stackshot_report()
    assert (report.product_type, report.build_version) == ("iPhone19,4", "24B91034")
    assert report.reason == "stackshot via sysdiagnose"
    assert report.notes == ["Requested by sysdiagnose_helper"]
    assert report.frontmost_pids == [77]
    assert report.__rich__().plain.splitlines()[3:] == [
        "Reason: stackshot via sysdiagnose",
        "Note: Requested by sysdiagnose_helper",
        "Device: iPhone19,4, iPhone OS 27.2.1 (24B91034)",
        "Kernel: Darwin Kernel Version 27.2.0",
        "Memory pages: active 5, free 7 (16384 bytes each)",
        "Processes: 3 (3 threads)",
        "Frontmost: food (pid 77)",
        "\tCall stacks are printed for the processes asked for, by name or pid.",
    ]


def test_stackshot_frames_without_symbols():
    kernel_task, food, _dext = stackshot_report().processes
    assert [
        (frame.kernel, frame.image, frame.address, frame.image_offset)
        for frame in kernel_task.threads[0].frames
    ] == [
        (True, "kernelcache", KERNEL_VMADDR + TEXT_EXEC + 0x110, None),
        # an image outside the kernelcache a kernel stack went through
        (True, EXCLAVE_UUID, 0x7FFC040, 0x40),
        (True, "kernelcache", KEXT_VMADDR + TEXT_EXEC + 0x180, None),
    ]
    # the shared cache is located where it is before sliding
    assert [(frame.kernel, frame.address) for frame in food.threads[0].frames] == [
        (False, SHARED_CACHE_BASE + 0x10104)
    ]


def test_stackshot_frames_are_named(
    symbols: DeviceSupportSymbols, kernel_symbols: KernelSymbols
):
    report = stackshot_report()
    report.device_support_symbols = symbols
    report.kernel_symbols = kernel_symbols

    kernel_task, food, dext = report.processes
    assert [
        (frame.image, frame.image_offset, frame.symbol, frame.symbol_offset)
        for frame in kernel_task.threads[0].frames
    ] == [
        ("com.apple.kernel", 0x110, "panic", 0x10),
        (EXCLAVE_UUID, 0x40, None, None),
        ("com.apple.driver.Foo", 0x180, "Foo_start", 0x80),
    ]
    frame = food.threads[0].frames[0]
    assert (frame.image, frame.symbol, frame.symbol_offset) == (
        "libfoo.dylib",
        "foo",
        4,
    )
    # DriverKit runs on a shared cache of its own, which these symbols are not of
    frame = dext.threads[0].frames[0]
    assert (frame.image, frame.symbol) == (DRIVERKIT_CACHE_UUID, None)


def test_stackshot_threads():
    report = stackshot_report()
    thread = report.find_processes("food")[0].threads[0]
    assert thread.state == ["TH_WAIT"]
    assert thread.wait_info == "mach_msg receive on port set 0x1"
    assert thread.queue == "com.food.queue"
    assert (thread.base_priority, thread.sched_priority) == (31, 47)
    assert (thread.user_usec, thread.system_usec) == (3, 4)
    assert not thread.running

    (running,) = report.running_processes
    assert (running.name, [thread.tid for thread in running.threads]) == (
        "kernel_task",
        [1],
    )
    assert report.render_processes(report.find_processes("77")).plain == (
        "Process: food (pid 77, 1 threads)\n"
        "\tThread: tid 500 [TH_WAIT]\n"
        "\t\tQueue: com.food.queue\n"
        "\t\tWaiting: mach_msg receive on port set 0x1\n"
        "\t\tpriority 47 (base 31), user 3 usec, system 4 usec\n"
        f"\t\tuser   [{SHARED_CACHE_UUID}] 0x{SHARED_CACHE_BASE + 0x10104:x} (+ 0x10104)\n"
    )


def test_stackshot_objects():
    report = stackshot_report()
    food = report.get_process(77)
    assert food is not None and report.get_process(1234) is None
    assert report.frontmost_processes == [food]
    assert (food.name, food.parent_pid, food.user_id, food.group_id) == (
        "food",
        1,
        501,
        501,
    )
    assert food.flags == ["foreground", "sharedRegionSystem"]
    assert food.frontmost and not report.get_process(0).frontmost
    assert food.resident_memory_bytes == 4096
    assert (food.user_time, food.system_time, food.uptime) == (1.5, 0.5, 282.0)
    # whatever has no field is still at hand
    assert food.raw["csFlags"] == 570434305

    thread = food.get_thread(500)
    assert thread is not None and food.get_thread(1) is None
    assert thread.qos == "QOS_CLASS_USER_INITIATED"
    assert thread.flags == ["kUser64_p"]
    assert thread.raw["lastRunTime"] == 0.99
    assert [frame.address for frame in thread.user_frames] == [
        SHARED_CACHE_BASE + 0x10104
    ]
    assert thread.kernel_frames == []
    assert len(report.get_process(0).threads[0].kernel_frames) == 3

    memory = report.memory_status
    assert memory is not None
    assert (memory.page_size, memory.pages) == (16384, {"active": 5, "free": 7})
    assert panic_report().memory_status is None

    # the names from when only panics had processes
    assert crash_report.PanicProcess is crash_report.StackshotProcess
    assert crash_report.PanicThread is crash_report.StackshotThread
    assert crash_report.PanicFrame is crash_report.StackshotFrame


@pytest.fixture
def stackshot_file(tmp_path: Path) -> Path:
    report_file = tmp_path / "stacks.ips"
    report_file.write_text(
        json.dumps({"bug_type": "288", "timestamp": "2026-11-17 04:24:10.00 -0800"})
        + "\n"
        + json.dumps(stackshot_report()._data)
    )
    return report_file


def test_cli_lists_the_threads_of_a_stackshot(stackshot_file: Path):
    result = RUNNER.invoke(app, [str(stackshot_file)])
    assert result.exit_code == 0, result.output
    assert "Reason: stackshot via sysdiagnose" in result.output
    assert "Process:" not in result.output

    result = RUNNER.invoke(app, [str(stackshot_file), "--running"])
    assert result.exit_code == 0, result.output
    assert "Process: kernel_task (pid 0, 1 threads)" in result.output
    assert "Thread: tid 1 idle #0 [TH_RUN, TH_IDLE]" in result.output
    assert "Process: food" not in result.output

    result = RUNNER.invoke(app, [str(stackshot_file), "-r", "-p", "food"])
    assert result.exit_code == 0, result.output
    assert "Process: kernel_task" in result.output
    assert "Process: food (pid 77, 1 threads)" in result.output


SPINDUMP_TEXT = f"""Date/Time:        2026-11-17 02:35:14.885 -0800
OS Version:       iPhone OS 27.2.1 (Build 24B91034)
Report Version:   73

Data Source:      Microstackshots
Shared Cache:     {SHARED_CACHE_UUID.upper()} slid base address 0x{SHARED_CACHE_BASE + SHARED_CACHE_SLIDE:x}

Command:          food
Path:             /usr/libexec/food
PID:              77

Event:            disk writes
Action taken:     none
Writes:           1073.75 MB of file backed memory dirtied over 67 seconds
Duration:         66.92s

Hardware model:   iPhone19,4
Active cpus:      6

Heaviest stack for the target process:
  5  ??? (food + 64) [0x104000040]
  5  ??? (libfoo.dylib + 516) [0x{LIBFOO_VMADDR + SHARED_CACHE_SLIDE + 0x204:x}]
  3  ??? (libfoo.dylib + 260) [0x{LIBFOO_VMADDR + SHARED_CACHE_SLIDE + 0x104:x}]


Powerstats for:   food [77]
UUID:             {DAEMON_UUID.upper()}
Path:             /usr/libexec/food
Num samples:      5 (100%)
  5  ??? (food + 64) [0x104000040]
    5  ??? (libfoo.dylib + 516) [0x{LIBFOO_VMADDR + SHARED_CACHE_SLIDE + 0x204:x}]
      3  ??? (libfoo.dylib + 260) [0x{LIBFOO_VMADDR + SHARED_CACHE_SLIDE + 0x104:x}]
        3   <on behalf of food [77] (originated by UNKNOWN [1])>
      2  already_named + 8 (libfoo.dylib + 780) [0x{LIBFOO_VMADDR + SHARED_CACHE_SLIDE + 0x30C:x}]

  Binary Images:
           0x104000000 -                ???  com.example.food 1.0 (2) <{DAEMON_UUID.upper()}>  /usr/libexec/food
           0x{LIBFOO_VMADDR + SHARED_CACHE_SLIDE:x} -        0x{LIBFOO_VMADDR + SHARED_CACHE_SLIDE + 0xFFF:x}  libfoo.dylib     <{LIBFOO_UUID.upper()}>  /usr/lib/libfoo.dylib


Powerstats for:   helperd
UUID:             AAAAAAAA-0000-1111-2222-333333333333
Num samples:      1 (20%)
  1  ??? (helperd + 16) [0x100000010]
  1  <Kernel mode>

  Binary Images:
           0x100000000 -                ???  helperd <AAAAAAAA-0000-1111-2222-333333333333>  /usr/libexec/helperd
"""


def spindump_report() -> SpindumpCrashReport:
    report = get_crash_report_from_buf(
        json.dumps(
            {
                "bug_type": "145",
                "timestamp": "2026-11-17 02:36:22.00 -0800",
                "incident_id": "ID",
            }
        )
        + "\n"
        + SPINDUMP_TEXT,
        filename="food.diskwrites_resource.ips",
    )
    assert isinstance(report, SpindumpCrashReport)
    return report


def test_spindump_summary():
    report = spindump_report()
    assert (report.event, report.command, report.pid) == ("disk writes", "food", 77)
    assert (report.product_type, report.build_version) == ("iPhone19,4", "24B91034")
    assert report.fields["Duration"] == "66.92s"
    assert report.__rich__().plain.splitlines()[3:] == [
        "Event: disk writes",
        "Process: food (pid 77)",
        "Action taken: none",
        "Writes: 1073.75 MB of file backed memory dirtied over 67 seconds",
        "Duration: 66.92s",
        "Device: iPhone19,4, iPhone OS 27.2.1 (Build 24B91034)",
        "Heaviest stack:",
        "\t5   [food] 0x104000040 (+ 0x40)",
        f"\t5   [libfoo.dylib] 0x{LIBFOO_VMADDR + SHARED_CACHE_SLIDE + 0x204:x} (+ 0x204)",
        f"\t3   [libfoo.dylib] 0x{LIBFOO_VMADDR + SHARED_CACHE_SLIDE + 0x104:x} (+ 0x104)",
        "\tFrames are named given the Xcode DeviceSupport of iPhone19,4 (24B91034).",
    ]


def test_spindump_processes():
    report = spindump_report()
    food, helperd = report.processes
    assert (food.name, food.pid, food.uuid, food.path) == (
        "food",
        77,
        DAEMON_UUID.upper(),
        "/usr/libexec/food",
    )
    assert report.target_process is food and report.get_process(77) is food
    assert (helperd.name, helperd.pid) == ("helperd", None)
    assert report.find_processes("helperd") == [helperd]

    # an image is named after its file, whatever identifier and version the report lists it by
    assert [(image.name, image.uuid, image.end) for image in food.images] == [
        ("food", DAEMON_UUID, None),
        ("libfoo.dylib", LIBFOO_UUID, LIBFOO_VMADDR + SHARED_CACHE_SLIDE + 0xFFF),
    ]

    (root,) = food.frames
    assert (root.count, root.image, root.image_offset) == (5, "food", 64)
    (caller,) = root.children
    leaf, named = caller.children
    assert (leaf.count, leaf.address) == (3, LIBFOO_VMADDR + SHARED_CACHE_SLIDE + 0x104)
    # a line which is not a frame
    assert [(note.address, note.note) for note in leaf.children] == [
        (None, "<on behalf of food [77] (originated by UNKNOWN [1])>")
    ]
    assert (named.symbol, named.symbol_offset) == ("already_named", 8)
    assert [depth for depth, _frame in food.walk()] == [0, 1, 2, 3, 2]
    assert [frame.note for frame in helperd.frames] == [None, "<Kernel mode>"]


def test_spindump_frames_are_named(symbols: DeviceSupportSymbols):
    report = spindump_report()
    report.device_support_symbols = symbols

    food = report.processes[0]
    frames = {frame.image_offset: frame for _depth, frame in food.walk()}
    # where a sample ended is where the thread was, the rest is where it returns to
    assert (frames[260].symbol, frames[260].symbol_offset) == ("foo", 4)
    assert (frames[516].symbol, frames[516].symbol_offset) == ("bar", 4)
    # the symbols do not hold the executables of processes, and a name the report gave is kept
    assert frames[64].symbol is None
    assert frames[780].symbol == "already_named"

    assert [(frame.symbol, frame.symbol_offset) for frame in report.heaviest_stack] == [
        (None, None),
        ("bar", 4),
        ("foo", 4),
    ]
    assert "Frames are named given" not in report.__rich__().plain


def test_cli_lists_the_call_tree_of_a_spindump_process(tmp_path: Path):
    report_file = tmp_path / "food.diskwrites_resource.ips"
    report_file.write_text(
        json.dumps({"bug_type": "145", "timestamp": "2026-11-17 02:36:22.00 -0800"})
        + "\n"
        + SPINDUMP_TEXT
    )
    result = RUNNER.invoke(app, [str(report_file)])
    assert result.exit_code == 0, result.output
    assert "Event: disk writes" in result.output
    assert "Process: helperd" not in result.output

    result = RUNNER.invoke(app, [str(report_file), "-p", "77"])
    assert result.exit_code == 0, result.output
    assert "Process: food (pid 77, samples: 5 (100%))" in result.output
    assert "    5   [libfoo.dylib]" in result.output
    assert "<on behalf of food [77] (originated by UNKNOWN [1])>" in result.output
    assert "Process: helperd" not in result.output

    result = RUNNER.invoke(app, [str(report_file), "--all"])
    assert "Process: helperd (samples: 1 (20%))" in result.output

    result = RUNNER.invoke(app, [str(report_file), "--running"])
    assert result.exit_code == 2
    assert "--running applies to panic and stackshot" in result.output


def test_user_mode_thread_without_a_call_stack_tells_where_it_resumes(
    symbols: DeviceSupportSymbols,
):
    payload = {
        "modelCode": "iPhone19,4",
        "osVersion": {"build": "24B91034"},
        "exception": {"type": "EXC_CRASH", "signal": "SIGABRT"},
        "faultingThread": 0,
        "usedImages": [
            {"base": 0x104000000, "size": 0x4000, "path": "/usr/libexec/food"},
            {
                "base": LIBFOO_VMADDR + SHARED_CACHE_SLIDE,
                "size": 0x1000,
                "uuid": LIBFOO_UUID,
                "path": "/usr/lib/libfoo.dylib",
            },
        ],
        "threads": [
            {
                "id": 500,
                "triggered": True,
                "threadState": {"pc": {"value": 0x104000040}},
                "frames": [{"imageIndex": 0, "imageOffset": 0x40}],
            },
            # an idle worker: parked, to resume at the start of a function
            {
                "id": 501,
                "threadState": {
                    "pc": {"value": LIBFOO_VMADDR + SHARED_CACHE_SLIDE + 0x200}
                },
                "frames": [],
            },
            # nowhere the report knows of
            {"id": 502, "threadState": {"pc": {"value": 0x7000}}, "frames": []},
            {"id": 503, "threadState": {}, "frames": []},
        ],
    }
    report = get_crash_report_from_buf(
        json.dumps({"bug_type": "309", "timestamp": "2026-11-16 17:35:06.00 +0200"})
        + "\n"
        + json.dumps(payload)
    )
    report.device_support_symbols = symbols

    crashed, parked, unknown, stateless = report.threads
    assert len(crashed.frames) == 1
    (frame,) = parked.frames
    assert (frame.image_name, frame.image_offset) == ("/usr/lib/libfoo.dylib", 0x200)
    assert (frame.symbol, frame.symbol_offset) == ("bar", 0)
    assert unknown.frames == [] and stateless.frames == []
    assert "(bar + 0x0)" in report.render_threads().plain
