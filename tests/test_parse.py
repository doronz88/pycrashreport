import json
import re
from datetime import datetime
from io import StringIO
from pathlib import Path

from rich.console import Console
from rich.text import Text

from pycrashreport.crash_report import (
    BugType,
    CrashReportBase,
    Frame,
    KernelModeCrashReport,
    Register,
    UserModeCrashReport,
    get_crash_report_from_buf,
    get_crash_report_from_file,
    parse_report,
)

REPORTS = Path(__file__).parent

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def test_non_symbolicated_ios14():
    crash_report = parse_report(
        REPORTS / "user_mode_crash_report_ios14_non_symbolicated_abort.ips"
    )
    assert isinstance(crash_report, UserModeCrashReport)
    assert crash_report.bug_type == BugType.Crash_109
    assert crash_report.incident_id == "13917FF0-E1B1-4652-84C2-85516D101DFE"
    assert crash_report.timestamp == datetime(2021, 10, 22, 0, 14, 53)
    assert crash_report.faulting_thread == 7
    assert crash_report.exception_type == "EXC_CRASH (SIGABRT)"
    assert crash_report.exception_subtype is None
    assert crash_report.application_specific_information == "abort() called"

    expected_registers = [
        Register(name="x0", value=0),
        Register(name="x1", value=0),
        Register(name="x2", value=0),
        Register(name="x3", value=0),
        Register(name="x4", value=0x000000016F6763D0),
        Register(name="x5", value=0x000000016F676970),
        Register(name="x6", value=0x0000000000000072),
        Register(name="x7", value=0x0000000000001800),
        Register(name="x8", value=0xE3E68C37E41B1559),
        Register(name="x9", value=0xE3F5EFB68B7C6559),
        Register(name="x10", value=0x0000000000000002),
        Register(name="x11", value=0x0000000000000003),
        Register(name="x12", value=0),
        Register(name="x13", value=0x00000000FFFFFFFF),
        Register(name="x14", value=0x0000000000000010),
        Register(name="x15", value=0),
        Register(name="x16", value=0x0000000000000148),
        Register(name="x17", value=0x000000016F677000),
        Register(name="x18", value=0),
        Register(name="x19", value=0x0000000000000006),
        Register(name="x20", value=0x0000000000001F3B),
        Register(name="x21", value=0x000000016F6770E0),
        Register(name="x22", value=0x0000000000000114),
        Register(name="x23", value=0),
        Register(name="x24", value=0),
        Register(name="x25", value=0x000000016F6770E0),
        Register(name="x26", value=0),
        Register(name="x27", value=0x000000016F677180),
        Register(name="x28", value=0x00000000000003FF),
        Register(name="fp", value=0x000000016F6768E0),
        Register(name="lr", value=0x00000001E18A1A9C),
        Register(name="sp", value=0x000000016F6768C0),
        Register(name="pc", value=0x00000001C3E1A334),
        Register(name="cpsr", value=0x40000000),
        Register(name="esr", value=0x0000000056000080),
    ]
    for i, register in enumerate(expected_registers):
        assert crash_report.registers[i] == register

    expected_frames = [
        Frame(
            image_name="libsystem_kernel.dylib",
            image_base=0x1C3DF1000,
            symbol=None,
            image_offset=168756,
            symbol_offset=None,
        ),
        Frame(
            image_name="libsystem_pthread.dylib",
            image_base=0x1E189F000,
            symbol=None,
            image_offset=10908,
            symbol_offset=None,
        ),
        Frame(
            image_name="libsystem_c.dylib",
            image_base=0x19EF2E000,
            symbol=None,
            image_offset=490372,
            symbol_offset=None,
        ),
        Frame(
            image_name="libc++abi.dylib",
            image_base=0x1AA804000,
            symbol=None,
            image_offset=80824,
            symbol_offset=None,
        ),
        Frame(
            image_name="libc++abi.dylib",
            image_base=0x1AA804000,
            symbol=None,
            image_offset=20168,
            symbol_offset=None,
        ),
        Frame(
            image_name="libobjc.A.dylib",
            image_base=0x1AA70E000,
            symbol=None,
            image_offset=28764,
            symbol_offset=None,
        ),
        Frame(
            image_name="libc++abi.dylib",
            image_base=0x1AA804000,
            symbol=None,
            image_offset=77728,
            symbol_offset=None,
        ),
        Frame(
            image_name="libc++abi.dylib",
            image_base=0x1AA804000,
            symbol=None,
            image_offset=77612,
            symbol_offset=None,
        ),
        Frame(
            image_name="libdispatch.dylib",
            image_base=0x1957C7000,
            symbol=None,
            image_offset=18480,
            symbol_offset=None,
        ),
        Frame(
            image_name="libdispatch.dylib",
            image_base=0x1957C7000,
            symbol=None,
            image_offset=31988,
            symbol_offset=None,
        ),
        Frame(
            image_name="libdispatch.dylib",
            image_base=0x1957C7000,
            symbol=None,
            image_offset=29572,
            symbol_offset=None,
        ),
        Frame(
            image_name="libdispatch.dylib",
            image_base=0x1957C7000,
            symbol=None,
            image_offset=90080,
            symbol_offset=None,
        ),
        Frame(
            image_name="libdispatch.dylib",
            image_base=0x1957C7000,
            symbol=None,
            image_offset=92120,
            symbol_offset=None,
        ),
        Frame(
            image_name="libsystem_pthread.dylib",
            image_base=0x1E189F000,
            symbol=None,
            image_offset=14184,
            symbol_offset=None,
        ),
        Frame(
            image_name="libsystem_pthread.dylib",
            image_base=0x1E189F000,
            symbol=None,
            image_offset=42828,
            symbol_offset=None,
        ),
    ]
    for i, frame in enumerate(expected_frames):
        assert frame == crash_report.frames[i]


def test_symbolicated_ios14():
    crash_report = parse_report(
        REPORTS / "user_mode_crash_report_ios14_symbolicated.ips"
    )
    assert isinstance(crash_report, UserModeCrashReport)
    assert crash_report.bug_type == BugType.Crash_109
    assert crash_report.incident_id == "2416C26A-72A8-4687-AFAA-7FCEB9D77458"
    assert crash_report.timestamp == datetime(2022, 1, 21, 18, 14, 26)
    assert crash_report.faulting_thread == 0
    assert crash_report.exception_type == "EXC_CRASH (SIGABRT)"
    assert crash_report.exception_subtype is None
    assert (
        crash_report.application_specific_information
        == "dyld3 mode\nstack buffer overflow"
    )

    expected_registers = [
        Register(name="x0", value=0x0000000000000000),
        Register(name="x1", value=0x0000000000000000),
        Register(name="x2", value=0x0000000000000000),
        Register(name="x3", value=0x0000000000000000),
        Register(name="x4", value=0x0000000000000000),
        Register(name="x5", value=0x0000000000000000),
        Register(name="x6", value=0x00676F6C7379732F),
        Register(name="x7", value=0xFFFFFFFFFFFFB5DC),
        Register(name="x8", value=0x000000010016F880),
        Register(name="x9", value=0xE021F14AD5B95AC2),
        Register(name="x10", value=0x0000000000000000),
        Register(name="x11", value=0x0000000000000038),
        Register(name="x12", value=0x00000001E5BF86C0),
        Register(name="x13", value=0x0000000089BFF7FB),
        Register(name="x14", value=0x0000000000000001),
        Register(name="x15", value=0x00000000001FF800),
        Register(name="x16", value=0x0000000000000148),
        Register(name="x17", value=0x0000030100000380),
        Register(name="x18", value=0x0000000000000000),
        Register(name="x19", value=0x0000000000000006),
        Register(name="x20", value=0x0000000000000103),
        Register(name="x21", value=0x000000010016F960),
        Register(name="x22", value=0x0000000000000000),
        Register(name="x23", value=0x0000000000000000),
        Register(name="x24", value=0x0000000000000000),
        Register(name="x25", value=0x0000000000000000),
        Register(name="x26", value=0x0000000000000000),
        Register(name="x27", value=0x0000000000000000),
        Register(name="x28", value=0x000000016FD83AF8),
        Register(name="fp", value=0x000000016FD839F0),
        Register(name="lr", value=0x00000001E5C049C4),
        Register(name="sp", value=0x000000016FD839D0),
        Register(name="pc", value=0x00000001C95957B0),
        Register(name="cpsr", value=0x40000000),
        Register(name="esr", value=0x56000080),
    ]
    for i, register in enumerate(expected_registers):
        assert crash_report.registers[i] == register

    expected_frames = [
        Frame(
            image_name="libsystem_kernel.dylib",
            image_base=None,
            symbol="__pthread_kill",
            image_offset=None,
            symbol_offset=8,
        ),
        Frame(
            image_name="libsystem_pthread.dylib",
            image_base=None,
            symbol="pthread_kill",
            image_offset=None,
            symbol_offset=212,
        ),
        Frame(
            image_name="libsystem_c.dylib",
            image_base=None,
            symbol="__abort",
            image_offset=None,
            symbol_offset=112,
        ),
        Frame(
            image_name="libsystem_c.dylib",
            image_base=None,
            symbol="a64l",
            image_offset=None,
            symbol_offset=0,
        ),
        Frame(
            image_name="kaki",
            image_base=None,
            symbol="main",
            image_offset=None,
            symbol_offset=108,
        ),
        Frame(
            image_name="libdyld.dylib",
            image_base=None,
            symbol="start",
            image_offset=None,
            symbol_offset=4,
        ),
    ]
    for i, frame in enumerate(expected_frames):
        assert frame == crash_report.frames[i]


def test_non_symbolicated_monterey():
    crash_report = parse_report(
        REPORTS / "user_mode_crash_report_monterey_non_symbolicated.ips"
    )
    assert isinstance(crash_report, UserModeCrashReport)
    assert crash_report.bug_type == BugType.Crash_309
    assert crash_report.incident_id == "051760D9-97FF-475F-8B61-B0FDFB04D484"
    assert crash_report.timestamp == datetime(2022, 1, 6, 15, 9, 22)
    assert crash_report.faulting_thread == 0
    assert crash_report.exception_type == "EXC_BAD_ACCESS"
    assert (
        crash_report.exception_subtype == "KERN_INVALID_ADDRESS at 0x0000000000000000"
    )
    assert crash_report.application_specific_information is None

    expected_registers = [
        Register(name="r13", value=140701961193192),
        Register(name="rax", value=4),
        Register(name="rflags", value=66119),
        Register(name="cpu", value=8),
        Register(name="r14", value=140701961192952),
        Register(name="rsi", value=0),
        Register(name="r8", value=32),
        Register(name="cr2", value=0),
        Register(name="rdx", value=1),
        Register(name="r10", value=1),
        Register(name="r9", value=187692599),
        Register(name="r15", value=140701961192952),
        Register(name="rbx", value=0),
        Register(name="trap", value=14),
        Register(name="err", value=20),
        Register(name="r11", value=582),
        Register(name="rip", value=0),
        Register(name="rbp", value=140701961192928),
        Register(name="rsp", value=140701961192872),
        Register(name="r12", value=4630279072),
        Register(name="rcx", value=140701961192872),
        Register(name="rdi", value=5123),
    ]
    for i, register in enumerate(expected_registers):
        assert crash_report.registers[i] == register

    expected_frames = [
        Frame(
            image_name=None,
            image_base=0,
            symbol=None,
            image_offset=0,
            symbol_offset=None,
        ),
        Frame(
            image_name="/usr/lib/system/libsystem_c.dylib",
            image_base=0x7FF80C65C000,
            symbol="nanosleep",
            image_offset=0x108A9,
            symbol_offset=0xC4,
        ),
        Frame(
            image_name="/bin/sleep",
            image_base=0x105857000,
            symbol=None,
            image_offset=0x3DD2,
            symbol_offset=None,
        ),
        Frame(
            image_name="/usr/lib/dyld",
            image_base=0x113F47000,
            symbol="start",
            image_offset=0x54FE,
            symbol_offset=0x1CE,
        ),
    ]
    for i, frame in enumerate(expected_frames):
        assert frame == crash_report.frames[i]


def test_forceReset_ios16():
    crash_report = parse_report(
        REPORTS / "kernel_mode_crash_report_ios16_forceReset-full.ips"
    )
    assert isinstance(crash_report, KernelModeCrashReport)
    assert crash_report.bug_type == BugType.ForceReset
    assert crash_report.incident_id == "35F77863-C28D-42BA-B633-9732EA1F342A"
    assert crash_report.timestamp == datetime(2022, 12, 24, 11, 43, 0, 470000)
    assert crash_report.panic_string == "btn_rst"
    assert crash_report.panic_caller == 0xFFFFFFF02E156784
    assert crash_report.debugger_message == "panic"
    assert crash_report.memory_id == 0x1
    assert crash_report.os_release_type == "Restore"
    assert crash_report.os_version == "20C65"
    assert (
        crash_report.kernel_version
        == "Darwin Kernel Version 22.2.0: Mon Nov 28 20:10:15 PST 2022; root:xnu-8792.62.2~1/RELEASE_ARM64_T8020"
    )
    assert crash_report.fileset_kernelcache_uuid == "8631036BCCCF5DE9E3270CDB30F5633F"
    assert crash_report.kernel_uuid == "E162E369-A92E-3EB7-872F-862218FB860F"
    assert crash_report.boot_session_uuid == "35F77863-C28D-42BA-B633-9732EA1F342A"
    assert crash_report.iboot_version == "iBoot-8419.60.44"
    assert crash_report.secure_boot is True
    assert crash_report.roots_installed == 0
    assert crash_report.paniclog_version == 14
    assert crash_report.panicked_task.address == 0xFFFFFFEADBA39378
    assert crash_report.panicked_task.pages == 0
    assert crash_report.panicked_task.threads == 263
    assert crash_report.panicked_task.pid == 0
    assert crash_report.panicked_task.name == "kernel_task"
    assert crash_report.panicked_thread.address == 0xFFFFFFE90ED3CED8
    assert crash_report.panicked_thread.backtrace == 0xFFFFFFECFB44F7E0
    assert crash_report.panicked_thread.tid == 798
    assert (
        crash_report.kernel_extensions_in_backtrace[0].name
        == "com.apple.driver.AppleM68Buttons"
    )
    assert crash_report.kernel_extensions_in_backtrace[0].version == "1.0d1"
    assert (
        crash_report.kernel_extensions_in_backtrace[0].uuid
        == "6AAC7152-26B3-355D-95F0-EC89EFA4152C"
    )
    assert (
        crash_report.last_started_kext
        == "com.apple.driver.ApplePearlSEPDriver\t1 (addr 0xfffffff02c64ab80, size 47123)"
    )
    assert crash_report.loaded_kexts[0] == "com.apple.driver.AppleUSBDeviceMux\t1.0.0d1"


FORCE_RESET_PANIC = "\n".join(
    [
        "panic(cpu 2 caller 0xfffffff01a2b3c4d): btn_rst",
        "Debugger message: panic",
        "Memory ID: 0x6",
        "OS release type: User",
        "OS version: 21A000",
        "Kernel version: Darwin Kernel Version 23.0.0: Thu Jan  1 00:00:00 PST 2026; root:xnu-1000.0.0~1/RELEASE_ARM64_T8101",
        "Fileset Kernelcache UUID: 0123456789ABCDEF0123456789ABCDEF",
        "Kernel UUID: 11111111-2222-3333-4444-555555555555",
        "Boot session UUID: 66666666-7777-8888-9999-AAAAAAAAAAAA",
        "iBoot version: iBoot-1000.0.0",
        "secure boot?: YES",
        "roots installed: 0",
        "Paniclog version: 14",
        "",
        "Panicked task 0xffffffe000001000: 0 pages, 250 threads: pid 0: kernel_task",
        "Panicked thread: 0xffffffe000002000, backtrace: 0xffffffe000003000, tid: 512",
        "\t\t  lr: 0xfffffff010000100  fp: 0xffffffe000003010",
        "      Kernel Extensions in backtrace:",
        "         com.example.driver.Buttons(1.0d1)[AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE]@0xfffffff010000000->0xfffffff010003fff",
        "            dependency: com.example.iokit.Family(2.0)[FFFFFFFF-0000-1111-2222-333333333333]@0xfffffff010004000->0xfffffff010007fff",
        "",
        "last started kext at 123456789: com.example.driver.Last\t1 (addr 0xfffffff011000000, size 4096)",
        "loaded kexts:",
        "com.example.driver.First\t1.0.0d1",
        "com.example.driver.Second\t2.0",
        "",
    ]
)


def force_reset_report() -> CrashReportBase:
    """A force-reset report in the layout the device writes: a metadata line, then a JSON body."""
    metadata = {
        "bug_type": "151",
        "timestamp": "2026-01-02 03:04:05.67 +0000",
        "os_version": "iPhone OS 17.0 (21A000)",
        "roots_installed": 0,
        "incident_id": "00000000-1111-2222-3333-444444444444",
    }
    body = {"build": "iPhone OS 17.0 (21A000)", "string": FORCE_RESET_PANIC}
    return get_crash_report_from_buf(
        json.dumps(metadata) + "\n" + json.dumps(body, indent=2),
        filename="forceReset-full.ips",
    )


def test_force_reset():
    crash_report = force_reset_report()
    assert isinstance(crash_report, KernelModeCrashReport)
    assert crash_report.bug_type == BugType.ForceReset
    assert crash_report.incident_id == "00000000-1111-2222-3333-444444444444"
    assert crash_report.timestamp == datetime(2026, 1, 2, 3, 4, 5, 670000)
    assert crash_report.panic_string == "btn_rst"
    assert crash_report.panic_caller == 0xFFFFFFF01A2B3C4D
    assert crash_report.debugger_message == "panic"
    assert crash_report.memory_id == 0x6
    assert crash_report.os_release_type == "User"
    assert crash_report.os_version == "21A000"
    assert crash_report.kernel_version == (
        "Darwin Kernel Version 23.0.0: Thu Jan  1 00:00:00 PST 2026; "
        "root:xnu-1000.0.0~1/RELEASE_ARM64_T8101"
    )
    assert crash_report.fileset_kernelcache_uuid == "0123456789ABCDEF0123456789ABCDEF"
    assert crash_report.kernel_uuid == "11111111-2222-3333-4444-555555555555"
    assert crash_report.boot_session_uuid == "66666666-7777-8888-9999-AAAAAAAAAAAA"
    assert crash_report.iboot_version == "iBoot-1000.0.0"
    assert crash_report.secure_boot is True
    assert crash_report.roots_installed == 0
    assert crash_report.paniclog_version == 14

    assert crash_report.panicked_task.address == 0xFFFFFFE000001000
    assert crash_report.panicked_task.pages == 0
    assert crash_report.panicked_task.threads == 250
    assert crash_report.panicked_task.pid == 0
    assert crash_report.panicked_task.name == "kernel_task"
    assert crash_report.panicked_thread.address == 0xFFFFFFE000002000
    assert crash_report.panicked_thread.backtrace == 0xFFFFFFE000003000
    assert crash_report.panicked_thread.tid == 512

    # the dependency line belongs to the extension above it, it is not one of its own
    (extension,) = crash_report.kernel_extensions_in_backtrace
    assert extension.name == "com.example.driver.Buttons"
    assert extension.version == "1.0d1"
    assert extension.uuid == "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
    assert extension.start == 0xFFFFFFF010000000
    assert extension.end == 0xFFFFFFF010003FFF

    assert crash_report.last_started_kext == (
        "com.example.driver.Last\t1 (addr 0xfffffff011000000, size 4096)"
    )
    assert crash_report.loaded_kexts == [
        "com.example.driver.First\t1.0.0d1",
        "com.example.driver.Second\t2.0",
    ]


def test_panic_210_with_panic_string_field():
    crash_report = get_crash_report_from_buf(
        "\n".join(
            [
                '{"bug_type":"210","timestamp":"2026-03-30 15:06:50.00 -0700","os_version":"iPhone OS 26.4 (23E246)","roots_installed":0,"incident_id":"66B11180-ED92-4FE0-9244-F3C9ACFBA8A6"}',
                '{"panicString":"panic(cpu 4 caller 0xfffffff015f5ba38): watchdog timeout\\nDebugger message: panic"}',
            ]
        ),
        filename="panic.ips",
    )
    assert crash_report.bug_type == BugType.Panic_210
    assert crash_report.panic_string == "watchdog timeout"
    assert crash_report.panic_caller == 0xFFFFFFF015F5BA38
    assert crash_report.debugger_message == "panic"


def test_bug_type_without_a_dedicated_parser():
    crash_report = get_crash_report_from_buf(
        '{"bug_type":"298","timestamp":"2026-01-02 03:04:05.00 +0000","incident_id":"ID"}\n'
        "anything"
    )
    assert type(crash_report) is CrashReportBase
    assert crash_report.bug_type == BugType("298")
    assert crash_report.timestamp == datetime(2026, 1, 2, 3, 4, 5)


def test_unknown_bug_type():
    crash_report = get_crash_report_from_buf(
        '{"bug_type":"not-a-bug-type","timestamp":"2026-01-02 03:04:05.00 +0000"}\n'
    )
    assert type(crash_report) is CrashReportBase
    assert crash_report.bug_type_str == "not-a-bug-type"


def test_every_listed_bug_type_selects_its_parser():
    for parser in (UserModeCrashReport, KernelModeCrashReport):
        assert parser.BUG_TYPES
        for bug_type in parser.BUG_TYPES:
            assert CrashReportBase.parser_for(bug_type.value) is parser


def test_user_mode_rendering():
    crash_report = parse_report(
        REPORTS / "user_mode_crash_report_ios14_symbolicated.ips"
    )
    rendered = crash_report.__rich__()
    assert isinstance(rendered, Text)
    lines = rendered.plain.splitlines()
    assert lines[0] == "2416C26A-72A8-4687-AFAA-7FCEB9D77458 2022-01-21 18:14:26"
    assert lines[1].endswith("user_mode_crash_report_ios14_symbolicated.ips")
    assert "Exception: EXC_CRASH (SIGABRT)" in lines
    assert "Registers:" in lines
    # four registers a row, each right-aligned in its own fixed-width cell
    first_row = lines[lines.index("Registers:") + 1]
    assert first_row == "".join(f"x{i} = 0x{0:016x} ".rjust(30) for i in range(4))
    assert "\t[kaki] _HEADER (main + 0x6c)" in lines


def test_kernel_mode_rendering():
    lines = force_reset_report().__rich__().plain.splitlines()
    assert lines[0] == "00000000-1111-2222-3333-444444444444 2026-01-02 03:04:05.670000"
    assert lines[1] == "forceReset-full.ips"
    assert lines[3:] == [
        "Panic: btn_rst",
        "Debugger message: panic",
        "Panicked task: kernel_task (pid 0, 250 threads)",
        "Panicked thread: tid 512 @ 0xffffffe000002000",
        "Kernel Extensions in backtrace:",
        "\tcom.example.driver.Buttons 1.0d1 [AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE]",
    ]


def test_str_is_colored(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    crash_report = force_reset_report()
    rendered = str(crash_report)
    assert "\x1b[" in rendered
    assert ANSI_ESCAPE.sub("", rendered) == crash_report.__rich__().plain.expandtabs(8)


def test_soft_wrap_keeps_lines_whole_on_a_narrow_console():
    crash_report = parse_report(
        REPORTS / "user_mode_crash_report_ios14_symbolicated.ips"
    )
    output = StringIO()
    Console(file=output, width=20).print(crash_report, soft_wrap=True, end="")
    assert output.getvalue() == crash_report.__rich__().plain.expandtabs(8)


def test_str_honors_no_color(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    rendered = str(force_reset_report())
    # NO_COLOR drops the colors (SGR 30-37) and leaves attributes such as bold and dim
    codes = {
        code
        for match in re.findall(r"\x1b\[([0-9;]*)m", rendered)
        for code in match.split(";")
    }
    assert codes <= {"0", "1", "2"}


def test_parse_report_accepts_a_path_or_a_string():
    path = REPORTS / "user_mode_crash_report_ios14_symbolicated.ips"
    for location in (path, str(path)):
        crash_report = parse_report(location)
        assert isinstance(crash_report, UserModeCrashReport)
        assert crash_report.filename == str(path)
        assert crash_report.incident_id == "2416C26A-72A8-4687-AFAA-7FCEB9D77458"


def test_parse_report_matches_parsing_an_open_file():
    path = REPORTS / "kernel_mode_crash_report_ios16_forceReset-full.ips"
    with open(path, encoding="utf-8") as report:
        from_file = get_crash_report_from_file(report)
    assert parse_report(path).__rich__().plain == from_file.__rich__().plain
