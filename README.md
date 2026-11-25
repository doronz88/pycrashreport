# Description

pyCrashReport in intended for analyzing crash reports from Apple devices into a clearer view, without all the thread
listing and loaded images, just the actual data you really need to debug the problem 😎.

Currently supported crash types:

- User mode crash reports
- Kernel mode crash reports
- Stackshots (`stacks-*.ips`, as sysdiagnose takes)
- Spindump reports of a process over a resource limit (`*.diskwrites_resource-*.ips`,
  `*.cpu_resource-*.ips`, `*.wakeups_resource-*.ips`)

All other crash reports will parse only basic metadata information.

# Installation

Using pip:

```shell
python3 -m pip install -U pycrashreport
```

# Usage

```shell
pycrashreport /path/to/report.ips
```

The output is colored with [rich](https://github.com/Textualize/rich) on a terminal, and plain
when piped.

From Python, a report is a rich renderable. `str(report)` gives the same text with ANSI colors
(set `NO_COLOR` to drop them), so a plain `print()` works too. Pass `soft_wrap=True` when printing
through a console, so long lines such as register rows are not reflowed to the terminal width:

```python
from rich.console import Console

from pycrashreport.crash_report import parse_report

report = parse_report("/path/to/report.ips")

Console().print(report, soft_wrap=True)  # colors follow the terminal
print(report)                            # always colored
print(report.bug_type, report.incident_id, report.timestamp)
```

`get_crash_report_from_file()` and `get_crash_report_from_buf()` parse an open file or a string
instead of a path.

A report class is picked by bug type. To parse another one, subclass `CrashReportBase` and list
the bug types it handles in `BUG_TYPES`.

## Userland crashes

A crash tells its process, what ended it and which thread crashed, before the registers and the
call stack of that thread. `--all` lists the call stack of every other thread as well:

```
Process: avconferenced (pid 469) /usr/libexec/avconferenced
Parent: launchd (pid 1)
Device: iPhone19,4 (24B91034)
Exception: EXC_CRASH (SIGABRT)
Exception Codes: 0x0000000000000000, 0x0000000000000000
Termination: SIGNAL, Abort trap: 6, by backboardd (pid 73)
Crashed thread: 0, tid 8152, queue com.apple.main-thread
```

From Python: `report.process_name`, `.pid`, `.process_path`, `.parent_name`, `.parent_pid`,
`.signal`, `.exception_codes`, `.termination` (as the report gives it), `.termination_reason` (the
line above) and `.threads`, each with its `tid`, `name`, `queue`, `crashed` and `frames`. A report
in the older text format has no `threads`.

A thread the report gives no call stack of has nothing to unwind: an idle worker of a dispatch
queue, for one, is parked in the kernel. It gets where it would resume as its only frame
(`start_wqthread + 0x0`).

## Exit reasons

A panic over a process which may not exit only gives the numbers of its exit reason. They are
named on the line below it, and in `report.exit_reason` (`namespace`, `namespace_name`, `subcode`,
`subcode_name`; `None` for any other panic):

```
Panic:  logd[26046] exited -- exit reason namespace 2 subcode 0x6 description: none
Exit reason: SIGNAL, SIGABRT
```

Every namespace is named. A code is named when its namespace gives it a fixed meaning that could
be read from XNU or from iOS (signals, jetsam, code signing, dyld, libxpc, exec, FrontBoard,
libsystem, the watchdog, guards and RealityKit), and printed as a number otherwise.

## Symbolication

A panic report gets the call stack of the thread which panicked, and `report.processes` holds the
stacks of every other thread it carries. Naming their frames takes symbols, through
[apple-symbols](https://github.com/doronz88/apple-symbols):

- **Userland frames** are named whenever this host holds the Xcode DeviceSupport of the device and
  build the report came from (`~/Library/Developer/Xcode/iOS DeviceSupport`, which Xcode or
  `pymobiledevice3 developer fetch-symbols download` fill). The same goes for the frames a userland
  crash report left unnamed. It holds the system libraries only, so frames of an executable keep
  their offset.
- **Kernel frames** need the kernelcache the device ran, and `ipsw` signatures to name the functions
  of a released one:

```shell
pycrashreport panic-full.ips --kernelcache kernelcache.release.iphone17 --kernel-signatures symbolicator/kernel
```

### From a symbolicator server

A [symbolicator-server](https://github.com/netanelc305/symbolicator-server) holds the symbols of
scanned IPSWs, so neither the DeviceSupport nor the kernelcache of the device has to be on this
host. Give its URL with `--server`, or once in `PYCRASHREPORT_SERVER`:

```shell
pycrashreport panic-full.ips --server http://localhost:3993
```

The server is asked first. Every frame it does not name is left to the symbols of this host, the
DeviceSupport and `--kernelcache`, which also name everything when the server does not hold the
build of the report. What the server could not help with is logged as a warning. A stackshot does
not tell which kernelcache the device ran, so the server is asked for the one of its device and
build which holds its kernel images.

`PYCRASHREPORT_SERVER` goes for every report parsed from Python as well, whatever parses it.
`report.symbol_server` holds the URL: assign another, or `None` for none, before reading any frame.
A server which cannot be reached raises `pycrashreport.symbols.SymbolServerError` once frames are
read.

`-p` (name or pid, may be given several times) lists the threads of further processes of the panic,
and `--all` those of every process:

```shell
pycrashreport panic-full.ips -p logd -p 1
pycrashreport panic-full.ips --all
```

## Stackshots

A stackshot carries the same processes and threads as a panic, of a system which keeps running. It
is summarized by why it was taken, the device, memory and the frontmost process; `-p`, `--all` and
`--running` (`-r`, only the threads which were on a CPU) print call stacks, each thread with its
state, what it waits on, its priority and the time it ran. `--kernelcache` and
`--kernel-signatures` name its kernel frames like those of a panic:

```shell
pycrashreport stacks.ips -p SpringBoard
pycrashreport stacks.ips --running --kernelcache kernelcache.release.iphone17 --kernel-signatures symbolicator/kernel
```

From Python, the report is a tree of plain objects: processes, their threads, and the frames of
each thread. `StackshotCrashReport` and `KernelModeCrashReport` share it (both are a
`StackshotReportBase`):

```python
from pycrashreport.crash_report import parse_report

report = parse_report("/path/to/stacks.ips")
print(report.reason, report.product_type, report.build_version, report.memory_status.pages["free"])

for process in report.frontmost_processes:  # also .processes, .running_processes, .get_process(pid),
    print(process.name, process.pid, process.parent_pid, process.resident_memory_bytes, process.flags)
    for thread in process.threads:          # .find_processes("name or pid")
        print(thread.tid, thread.name, thread.state, thread.wait_info, thread.sched_priority)
        for frame in thread.frames:         # or .kernel_frames / .user_frames
            print(hex(frame.address), frame.image, frame.symbol, frame.symbol_offset)
```

A field the objects do not have is still at hand as the report gave it, in `process.raw` and
`thread.raw`.

```python
from pathlib import Path

from apple_symbols import DeviceSupportSymbols, KernelSymbols

report = parse_report("/path/to/panic-full.ips")
# set before reading any frames; DeviceSupport is otherwise looked up by itself
report.device_support_symbols = DeviceSupportSymbols.load(Path("/path/to/Symbols"))
report.kernel_symbols = KernelSymbols.load(Path("kernelcache.release.iphone17"))
for frame in report.panicked_thread_frames:
    print(frame.image, frame.symbol, frame.symbol_offset)
```

## Spindump reports

A process which went over its limit of disk writes, CPU or wakeups gets a report of the samples
taken of it meanwhile, with not one of its frames named. It is summarized by the event and the
heaviest stack of the process, its frames named given the Xcode DeviceSupport of the device; `-p`
and `--all` print the call tree of the processes sampled, each frame after its count of samples:

```
Event: disk writes
Process: siriactionsd (pid 140)
Writes: 1073.75 MB of file backed memory dirtied over 67 seconds (16.05 MB per second average), exceeding limit of 12.43 KB per second over 86400 seconds
Heaviest stack:
	17  [libsqlite3.dylib] 0x1b25765b0 (sqlite3_step + 0x3bc)
	17  [libsystem_kernel.dylib] 0x24c697b54 (guarded_pwrite_np + 0x8)
```

```python
report = parse_report("/path/to/siriactionsd.diskwrites_resource.ips")
print(report.event, report.command, report.pid, report.fields["Writes"])
for frame in report.heaviest_stack:
    print(frame.count, frame.image, frame.symbol, frame.symbol_offset)
for process in report.processes:            # also .target_process, .get_process(pid), .find_processes()
    for depth, frame in process.walk():     # or process.frames and frame.children
        print("  " * depth, frame.count, frame.image, hex(frame.address or 0), frame.symbol or frame.note)
```

`render_processes(report, processes, all_processes, running)` renders what `-p`, `--all` and
`--running` print, for whichever kind of report holds processes.

# Usage examples

## iOS crash dumps

```
➜  pycrashreport tests/user_mode_crash_report_ios14_non_symbolicated_abort.ips
13917FF0-E1B1-4652-84C2-85516D101DFE 2021-10-22 00:14:53
tests/user_mode_crash_report_ios14_non_symbolicated_abort.ips

Process: itunescloudd [692] /System/Library/PrivateFrameworks/iTunesCloud.framework/Support/itunescloudd
Device: iPhone11,8 (18H17)
Exception: EXC_CRASH (SIGABRT)
Exception Codes: 0x0000000000000000, 0x0000000000000000
Application Specific Information: abort() called
Registers:
      x0 = 0x0000000000000000       x1 = 0x0000000000000000       x2 = 0x0000000000000000       x3 = 0x0000000000000000
      x4 = 0x000000016f6763d0       x5 = 0x000000016f676970       x6 = 0x0000000000000072       x7 = 0x0000000000001800
      x8 = 0xe3e68c37e41b1559       x9 = 0xe3f5efb68b7c6559      x10 = 0x0000000000000002      x11 = 0x0000000000000003
     x12 = 0x0000000000000000      x13 = 0x00000000ffffffff      x14 = 0x0000000000000010      x15 = 0x0000000000000000
     x16 = 0x0000000000000148      x17 = 0x000000016f677000      x18 = 0x0000000000000000      x19 = 0x0000000000000006
     x20 = 0x0000000000001f3b      x21 = 0x000000016f6770e0      x22 = 0x0000000000000114      x23 = 0x0000000000000000
     x24 = 0x0000000000000000      x25 = 0x000000016f6770e0      x26 = 0x0000000000000000      x27 = 0x000000016f677180
     x28 = 0x00000000000003ff       fp = 0x000000016f6768e0       lr = 0x00000001e18a1a9c       sp = 0x000000016f6768c0
      pc = 0x00000001c3e1a334     cpsr = 0x0000000040000000      esr = 0x0000000056000080

Frames:
        [libsystem_kernel.dylib] 0x1c3df1000 + 0x29334
        [libsystem_pthread.dylib] 0x1e189f000 + 0x2a9c
        [libsystem_c.dylib] 0x19ef2e000 + 0x77b84
        [libc++abi.dylib] 0x1aa804000 + 0x13bb8
        [libc++abi.dylib] 0x1aa804000 + 0x4ec8
        [libobjc.A.dylib] 0x1aa70e000 + 0x705c
        [libc++abi.dylib] 0x1aa804000 + 0x12fa0
        [libc++abi.dylib] 0x1aa804000 + 0x12f2c
        [libdispatch.dylib] 0x1957c7000 + 0x4830
        [libdispatch.dylib] 0x1957c7000 + 0x7cf4
        [libdispatch.dylib] 0x1957c7000 + 0x7384
        [libdispatch.dylib] 0x1957c7000 + 0x15fe0
        [libdispatch.dylib] 0x1957c7000 + 0x167d8
        [libsystem_pthread.dylib] 0x1e189f000 + 0x3768
        [libsystem_pthread.dylib] 0x1e189f000 + 0xa74c
```

## macOS intel dumps

```
➜  pycrashreport tests/user_mode_crash_report_monterey_non_symbolicated.ips
051760D9-97FF-475F-8B61-B0FDFB04D484 2022-01-06 15:09:22
tests/user_mode_crash_report_monterey_non_symbolicated.ips

Process: sleep (pid 10277) /bin/sleep
Parent: zsh (pid 10192)
Device: MacBookPro15,1 (21C52)
Exception: EXC_BAD_ACCESS (SIGSEGV)
Exception Subtype: KERN_INVALID_ADDRESS at 0x0000000000000000
Exception Codes: 0x0000000000000001, 0x0000000000000000
Termination: SIGNAL, Segmentation fault: 11, by exc handler (pid 10277)
Crashed thread: 0, tid 135513, queue com.apple.main-thread

Registers:
     r13 = 0x00007ff7ba6a86e8      rax = 0x0000000000000004   rflags = 0x0000000000010247      cpu = 0x0000000000000008
     r14 = 0x00007ff7ba6a85f8      rsi = 0x0000000000000000       r8 = 0x0000000000000020      cr2 = 0x0000000000000000
     rdx = 0x0000000000000001      r10 = 0x0000000000000001       r9 = 0x000000000b2ff637      r15 = 0x00007ff7ba6a85f8
     rbx = 0x0000000000000000     trap = 0x000000000000000e      err = 0x0000000000000014      r11 = 0x0000000000000246
     rip = 0x0000000000000000      rbp = 0x00007ff7ba6a85e0      rsp = 0x00007ff7ba6a85a8      r12 = 0x0000000113fc73a0
     rcx = 0x00007ff7ba6a85a8      rdi = 0x0000000000001403

Frames:
        [None] 0x0
        [/usr/lib/system/libsystem_c.dylib] 0x7ff80c65c000 + 0x108a9 (nanosleep + 0xc4)
        [/bin/sleep] 0x105857000 + 0x3dd2
        [/usr/lib/dyld] 0x113f47000 + 0x54fe (start + 0x1ce)
```
