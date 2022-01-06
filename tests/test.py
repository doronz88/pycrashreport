from pathlib import Path

from pycrashreport.crash_report import CrashReport, Frame, Register


def test_non_symbolicated_ios14():
    filename = str(Path(__file__).parent / 'crash_report_ios14_non_symbolicated_abort.ips')
    with open(filename) as f:
        buf = f.read()

    crash_report = CrashReport(buf, filename=filename)
    assert crash_report.bug_type == '109'
    assert crash_report.incident_id == '13917FF0-E1B1-4652-84C2-85516D101DFE'
    assert crash_report.timestamp == '2021-10-22 00:14:53.00 +0300'
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
    ]
    for i, register in enumerate(expected_registers):
        assert crash_report.registers[i] == register

    expected_frames = [
        Frame(image_name='libsystem_kernel.dylib', image_base=0x1c3df1000, symbol='0x00000001c3e1a334', offset=168756),
        Frame(image_name='libsystem_pthread.dylib', image_base=0x1e189f000, symbol='0x00000001e18a1a9c', offset=10908),
        Frame(image_name='libsystem_c.dylib', image_base=0x19ef2e000, symbol='0x000000019efa5b84', offset=490372),
        Frame(image_name='libc++abi.dylib', image_base=0x1aa804000, symbol='0x00000001aa817bb8', offset=80824),
        Frame(image_name='libc++abi.dylib', image_base=0x1aa804000, symbol='0x00000001aa808ec8', offset=20168),
        Frame(image_name='libobjc.A.dylib', image_base=0x1aa70e000, symbol='0x00000001aa71505c', offset=28764),
        Frame(image_name='libc++abi.dylib', image_base=0x1aa804000, symbol='0x00000001aa816fa0', offset=77728),
        Frame(image_name='libc++abi.dylib', image_base=0x1aa804000, symbol='0x00000001aa816f2c', offset=77612),
        Frame(image_name='libdispatch.dylib', image_base=0x1957c7000, symbol='0x00000001957cb830', offset=18480),
        Frame(image_name='libdispatch.dylib', image_base=0x1957c7000, symbol='0x00000001957cecf4', offset=31988),
        Frame(image_name='libdispatch.dylib', image_base=0x1957c7000, symbol='0x00000001957ce384', offset=29572),
        Frame(image_name='libdispatch.dylib', image_base=0x1957c7000, symbol='0x00000001957dcfe0', offset=90080),
        Frame(image_name='libdispatch.dylib', image_base=0x1957c7000, symbol='0x00000001957dd7d8', offset=92120),
        Frame(image_name='libsystem_pthread.dylib', image_base=0x1e189f000, symbol='0x00000001e18a2768', offset=14184),
        Frame(image_name='libsystem_pthread.dylib', image_base=0x1e189f000, symbol='0x00000001e18a974c', offset=42828),

    ]
    for i, frame in enumerate(expected_frames):
        assert frame == crash_report.frames[i]
