from datetime import datetime
from pathlib import Path

from pycrashreport.crash_report import BugType, Frame, Register, get_crash_report_from_file


def test_non_symbolicated_ios14():
    filename = Path(__file__).parent / 'user_mode_crash_report_ios14_non_symbolicated_abort.ips'
    crash_report = get_crash_report_from_file(open(filename, 'rt'))
    assert crash_report.bug_type == BugType.Crash_109
    assert crash_report.incident_id == '13917FF0-E1B1-4652-84C2-85516D101DFE'
    assert crash_report.timestamp == datetime(2021, 10, 22, 0, 14, 53)
    assert crash_report.faulting_thread == 7
    assert crash_report.exception_type == 'EXC_CRASH (SIGABRT)'
    assert crash_report.exception_subtype is None
    assert crash_report.application_specific_information == 'abort() called'

    expected_registers = [
        Register(name='x0', value=0),
        Register(name='x1', value=0),
        Register(name='x2', value=0),
        Register(name='x3', value=0),
        Register(name='x4', value=0x000000016f6763d0),
        Register(name='x5', value=0x000000016f676970),
        Register(name='x6', value=0x0000000000000072),
        Register(name='x7', value=0x0000000000001800),
        Register(name='x8', value=0xe3e68c37e41b1559),
        Register(name='x9', value=0xe3f5efb68b7c6559),
        Register(name='x10', value=0x0000000000000002),
        Register(name='x11', value=0x0000000000000003),
        Register(name='x12', value=0),
        Register(name='x13', value=0x00000000ffffffff),
        Register(name='x14', value=0x0000000000000010),
        Register(name='x15', value=0),
        Register(name='x16', value=0x0000000000000148),
        Register(name='x17', value=0x000000016f677000),
        Register(name='x18', value=0),
        Register(name='x19', value=0x0000000000000006),
        Register(name='x20', value=0x0000000000001f3b),
        Register(name='x21', value=0x000000016f6770e0),
        Register(name='x22', value=0x0000000000000114),
        Register(name='x23', value=0),
        Register(name='x24', value=0),
        Register(name='x25', value=0x000000016f6770e0),
        Register(name='x26', value=0),
        Register(name='x27', value=0x000000016f677180),
        Register(name='x28', value=0x00000000000003ff),
        Register(name='fp', value=0x000000016f6768e0),
        Register(name='lr', value=0x00000001e18a1a9c),
        Register(name='sp', value=0x000000016f6768c0),
        Register(name='pc', value=0x00000001c3e1a334),
        Register(name='cpsr', value=0x40000000),
        Register(name='esr', value=0x0000000056000080),
    ]
    for i, register in enumerate(expected_registers):
        assert crash_report.registers[i] == register

    expected_frames = [
        Frame(image_name='libsystem_kernel.dylib', image_base=0x1c3df1000, symbol=None,
              image_offset=168756, symbol_offset=None),
        Frame(image_name='libsystem_pthread.dylib', image_base=0x1e189f000, symbol=None,
              image_offset=10908, symbol_offset=None),
        Frame(image_name='libsystem_c.dylib', image_base=0x19ef2e000, symbol=None, image_offset=490372,
              symbol_offset=None),
        Frame(image_name='libc++abi.dylib', image_base=0x1aa804000, symbol=None, image_offset=80824,
              symbol_offset=None),
        Frame(image_name='libc++abi.dylib', image_base=0x1aa804000, symbol=None, image_offset=20168,
              symbol_offset=None),
        Frame(image_name='libobjc.A.dylib', image_base=0x1aa70e000, symbol=None, image_offset=28764,
              symbol_offset=None),
        Frame(image_name='libc++abi.dylib', image_base=0x1aa804000, symbol=None, image_offset=77728,
              symbol_offset=None),
        Frame(image_name='libc++abi.dylib', image_base=0x1aa804000, symbol=None, image_offset=77612,
              symbol_offset=None),
        Frame(image_name='libdispatch.dylib', image_base=0x1957c7000, symbol=None, image_offset=18480,
              symbol_offset=None),
        Frame(image_name='libdispatch.dylib', image_base=0x1957c7000, symbol=None, image_offset=31988,
              symbol_offset=None),
        Frame(image_name='libdispatch.dylib', image_base=0x1957c7000, symbol=None, image_offset=29572,
              symbol_offset=None),
        Frame(image_name='libdispatch.dylib', image_base=0x1957c7000, symbol=None, image_offset=90080,
              symbol_offset=None),
        Frame(image_name='libdispatch.dylib', image_base=0x1957c7000, symbol=None, image_offset=92120,
              symbol_offset=None),
        Frame(image_name='libsystem_pthread.dylib', image_base=0x1e189f000, symbol=None,
              image_offset=14184, symbol_offset=None),
        Frame(image_name='libsystem_pthread.dylib', image_base=0x1e189f000, symbol=None,
              image_offset=42828, symbol_offset=None),

    ]
    for i, frame in enumerate(expected_frames):
        assert frame == crash_report.frames[i]


def test_symbolicated_ios14():
    filename = str(Path(__file__).parent / 'user_mode_crash_report_ios14_symbolicated.ips')
    crash_report = get_crash_report_from_file(open(filename, 'rt'))
    assert crash_report.bug_type == BugType.Crash_109
    assert crash_report.incident_id == '2416C26A-72A8-4687-AFAA-7FCEB9D77458'
    assert crash_report.timestamp == datetime(2022, 1, 21, 18, 14, 26)
    assert crash_report.faulting_thread == 0
    assert crash_report.exception_type == 'EXC_CRASH (SIGABRT)'
    assert crash_report.exception_subtype is None
    assert crash_report.application_specific_information == 'dyld3 mode\nstack buffer overflow'

    expected_registers = [
        Register(name='x0', value=0x0000000000000000),
        Register(name='x1', value=0x0000000000000000),
        Register(name='x2', value=0x0000000000000000),
        Register(name='x3', value=0x0000000000000000),
        Register(name='x4', value=0x0000000000000000),
        Register(name='x5', value=0x0000000000000000),
        Register(name='x6', value=0x00676f6c7379732f),
        Register(name='x7', value=0xffffffffffffb5dc),
        Register(name='x8', value=0x000000010016f880),
        Register(name='x9', value=0xe021f14ad5b95ac2),
        Register(name='x10', value=0x0000000000000000),
        Register(name='x11', value=0x0000000000000038),
        Register(name='x12', value=0x00000001e5bf86c0),
        Register(name='x13', value=0x0000000089bff7fb),
        Register(name='x14', value=0x0000000000000001),
        Register(name='x15', value=0x00000000001ff800),
        Register(name='x16', value=0x0000000000000148),
        Register(name='x17', value=0x0000030100000380),
        Register(name='x18', value=0x0000000000000000),
        Register(name='x19', value=0x0000000000000006),
        Register(name='x20', value=0x0000000000000103),
        Register(name='x21', value=0x000000010016f960),
        Register(name='x22', value=0x0000000000000000),
        Register(name='x23', value=0x0000000000000000),
        Register(name='x24', value=0x0000000000000000),
        Register(name='x25', value=0x0000000000000000),
        Register(name='x26', value=0x0000000000000000),
        Register(name='x27', value=0x0000000000000000),
        Register(name='x28', value=0x000000016fd83af8),
        Register(name='fp', value=0x000000016fd839f0),
        Register(name='lr', value=0x00000001e5c049c4),
        Register(name='sp', value=0x000000016fd839d0),
        Register(name='pc', value=0x00000001c95957b0),
        Register(name='cpsr', value=0x40000000),
        Register(name='esr', value=0x56000080),
    ]
    for i, register in enumerate(expected_registers):
        assert crash_report.registers[i] == register

    expected_frames = [
        Frame(image_name='libsystem_kernel.dylib', image_base=None, symbol='__pthread_kill',
              image_offset=None, symbol_offset=8),
        Frame(image_name='libsystem_pthread.dylib', image_base=None, symbol='pthread_kill',
              image_offset=None, symbol_offset=212),
        Frame(image_name='libsystem_c.dylib', image_base=None, symbol='__abort', image_offset=None,
              symbol_offset=112),
        Frame(image_name='libsystem_c.dylib', image_base=None, symbol='a64l', image_offset=None,
              symbol_offset=0),
        Frame(image_name='kaki', image_base=None, symbol='main', image_offset=None,
              symbol_offset=108),
        Frame(image_name='libdyld.dylib', image_base=None, symbol='start', image_offset=None,
              symbol_offset=4),

    ]
    for i, frame in enumerate(expected_frames):
        assert frame == crash_report.frames[i]


def test_non_symbolicated_monterey():
    filename = str(Path(__file__).parent / 'user_mode_crash_report_monterey_non_symbolicated.ips')
    crash_report = get_crash_report_from_file(open(filename, 'rt'))
    assert crash_report.bug_type == BugType.Crash_309
    assert crash_report.incident_id == '051760D9-97FF-475F-8B61-B0FDFB04D484'
    assert crash_report.timestamp == datetime(2022, 1, 6, 15, 9, 22)
    assert crash_report.faulting_thread == 0
    assert crash_report.exception_type == 'EXC_BAD_ACCESS'
    assert crash_report.exception_subtype == 'KERN_INVALID_ADDRESS at 0x0000000000000000'
    assert crash_report.application_specific_information is None

    expected_registers = [
        Register(name='r13', value=140701961193192),
        Register(name='rax', value=4),
        Register(name='rflags', value=66119),
        Register(name='cpu', value=8),
        Register(name='r14', value=140701961192952),
        Register(name='rsi', value=0),
        Register(name='r8', value=32),
        Register(name='cr2', value=0),
        Register(name='rdx', value=1),
        Register(name='r10', value=1),
        Register(name='r9', value=187692599),
        Register(name='r15', value=140701961192952),
        Register(name='rbx', value=0),
        Register(name='trap', value=14),
        Register(name='err', value=20),
        Register(name='r11', value=582),
        Register(name='rip', value=0),
        Register(name='rbp', value=140701961192928),
        Register(name='rsp', value=140701961192872),
        Register(name='r12', value=4630279072),
        Register(name='rcx', value=140701961192872),
        Register(name='rdi', value=5123),
    ]
    for i, register in enumerate(expected_registers):
        assert crash_report.registers[i] == register

    expected_frames = [
        Frame(image_name=None, image_base=0, symbol=None, image_offset=0, symbol_offset=None),
        Frame(image_name='/usr/lib/system/libsystem_c.dylib', image_base=0x7ff80c65c000, symbol='nanosleep',
              image_offset=0x108a9, symbol_offset=0xc4),
        Frame(image_name='/bin/sleep', image_base=0x105857000, symbol=None, image_offset=0x3dd2, symbol_offset=None),
        Frame(image_name='/usr/lib/dyld', image_base=0x113f47000, symbol='start', image_offset=0x54fe,
              symbol_offset=0x1ce),
    ]
    for i, frame in enumerate(expected_frames):
        assert frame == crash_report.frames[i]


def test_forceReset_ios16():
    filename = str(Path(__file__).parent / 'kernel_mode_crash_report_ios16_forceReset-full.ips')
    crash_report = get_crash_report_from_file(open(filename, 'rt'))
    assert crash_report.bug_type == BugType.ForceReset
    assert crash_report.incident_id == '35F77863-C28D-42BA-B633-9732EA1F342A'
    assert crash_report.timestamp == datetime(2022, 12, 24, 11, 43, 0, 470000)
