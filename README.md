# Description

pyCrashReport in intended for analyzing crash reports from Apple devices into a clearer view, without all the thread
listing and loaded images, just the actual data you really need to debug the problem 😎.

# Installation

Using pip:

```shell
python3 -m pip install --user -U pycrashreport
```

# Usage

```
➜  pycrashreport git:(master) ✗ pycrashreport /tmp/itunescloudd-2021-10-22-001453.ips
13917FF0-E1B1-4652-84C2-85516D101DFE 2021-10-22 00:14:53.00 +0300
/tmp/itunescloudd-2021-10-22-001453.ips

Exception: EXC_CRASH (SIGABRT)
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
