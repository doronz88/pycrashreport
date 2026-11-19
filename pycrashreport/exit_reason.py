"""Names of the exit reasons the kernel reports a process to have ended with.

An exit reason is a namespace and a code that only means something inside that namespace. Each
table says where its values were read: XNU headers of ``xnu-12377.121.6``
(https://github.com/apple-oss-distributions/xnu) wherever they are public, and otherwise the
binaries of iOS 27.2 which tell them apart. Namespaces with no table here keep their codes in
closed sources, or give them no fixed meaning (a payload, a bit field).
"""

import re
from dataclasses import dataclass
from typing import Dict, Optional

#: ``OS_REASON_*`` of ``bsd/sys/reason.h``
NAMESPACES: Dict[int, str] = {
    0: "INVALID",
    1: "JETSAM",
    2: "SIGNAL",
    3: "CODESIGNING",
    4: "HANGTRACER",
    5: "TEST",
    6: "DYLD",
    7: "LIBXPC",
    8: "OBJC",
    9: "EXEC",
    10: "SPRINGBOARD",
    11: "TCC",
    12: "REPORTCRASH",
    13: "COREANIMATION",
    14: "AGGREGATED",
    15: "RUNNINGBOARD",
    16: "SKYWALK",
    17: "SETTINGS",
    18: "LIBSYSTEM",
    19: "FOUNDATION",
    20: "WATCHDOG",
    21: "METAL",
    22: "WATCHKIT",
    23: "GUARD",
    24: "ANALYTICS",
    25: "SANDBOX",
    26: "SECURITY",
    27: "ENDPOINTSECURITY",
    28: "PAC_EXCEPTION",
    29: "BLUETOOTH_CHIP",
    30: "PORT_SPACE",
    31: "WEBKIT",
    32: "BACKLIGHTSERVICES",
    33: "MEDIA",
    34: "ROSETTA",
    35: "LIBIGNITION",
    36: "BOOTMOUNT",
    37: "MTE_FAIL",
    38: "REALITYKIT",
    39: "AUDIO",
    40: "WAKEBOARD",
    41: "CORERC",
    42: "SELF_RESTRICT",
    43: "ARKIT",
    44: "CAMERA",
    45: "BACKBOARD",
    46: "POWEREXCEPTIONS",
    47: "SECINIT",
    # The header and iOS 27.2 disagree on the last two, so both names are given: the header says
    # SECURITY_SOFT_TRAPS and RESOURCES, -[OSACrashReport decode_reasonNamespace] of ReportCrash
    # says LIBCXX_SOFT_TRAP and BOUNDS_SAFETY_SOFT_TRAP (and libsystem_sanitizers.dylib does
    # report its bounds safety traps under 49).
    48: "SECURITY_SOFT_TRAPS/LIBCXX_SOFT_TRAP",
    49: "RESOURCES/BOUNDS_SAFETY_SOFT_TRAP",
}

#: ``JETSAM_REASON_*`` of ``bsd/sys/kern_memorystatus.h``
_JETSAM = {
    0: "INVALID",
    1: "GENERIC",
    2: "MEMORY_HIGHWATER",
    3: "VNODE",
    4: "MEMORY_VMPAGESHORTAGE",
    5: "MEMORY_PROCTHRASHING",
    6: "MEMORY_FCTHRASHING",
    7: "MEMORY_PERPROCESSLIMIT",
    8: "MEMORY_DISK_SPACE_SHORTAGE",
    9: "MEMORY_IDLE_EXIT",
    10: "ZONE_MAP_EXHAUSTION",
    11: "MEMORY_VMCOMPRESSOR_THRASHING",
    12: "MEMORY_VMCOMPRESSOR_SPACE_SHORTAGE",
    13: "LOWSWAP",
    14: "MEMORY_SUSTAINED_PRESSURE",
    15: "MEMORY_VMPAGEOUT_STARVATION",
    16: "MEMORY_CONCLAVELIMIT",
    17: "MEMORY_LONGIDLE_EXIT",
    100: "CPULIMIT",
}

#: ``SIG*`` of ``bsd/sys/signal.h``
_SIGNAL = {
    1: "SIGHUP",
    2: "SIGINT",
    3: "SIGQUIT",
    4: "SIGILL",
    5: "SIGTRAP",
    6: "SIGABRT",
    7: "SIGEMT",
    8: "SIGFPE",
    9: "SIGKILL",
    10: "SIGBUS",
    11: "SIGSEGV",
    12: "SIGSYS",
    13: "SIGPIPE",
    14: "SIGALRM",
    15: "SIGTERM",
    16: "SIGURG",
    17: "SIGSTOP",
    18: "SIGTSTP",
    19: "SIGCONT",
    20: "SIGCHLD",
    21: "SIGTTIN",
    22: "SIGTTOU",
    23: "SIGIO",
    24: "SIGXCPU",
    25: "SIGXFSZ",
    26: "SIGVTALRM",
    27: "SIGPROF",
    28: "SIGWINCH",
    29: "SIGINFO",
    30: "SIGUSR1",
    31: "SIGUSR2",
}

#: ``CODESIGNING_EXIT_REASON_*`` of ``bsd/sys/reason.h``
_CODESIGNING = {
    1: "TASKGATED_INVALID_SIG",
    2: "INVALID_PAGE",
    3: "TASK_ACCESS_PORT",
    4: "LAUNCH_CONSTRAINT_VIOLATION",
}

#: ``DYLD_EXIT_REASON_*`` of ``include/mach-o/dyld_priv.h``, ``dyld-1378``
#: (https://github.com/apple-oss-distributions/dyld)
_DYLD = {
    1: "DYLIB_MISSING",
    2: "DYLIB_WRONG_ARCH",
    3: "DYLIB_WRONG_VERSION",
    4: "SYMBOL_MISSING",
    5: "CODE_SIGNATURE",
    6: "FILE_SYSTEM_SANDBOX",
    7: "MALFORMED_MACHO",
    9: "OTHER",
    10: "DLSYM_BLOCKED",
}

#: ``XPC_EXIT_REASON_*``, the labels ``xpc_exit_reason_get_label()`` of libxpc.dylib looks up
_LIBXPC = {
    1: "RESERVED",
    2: "UNKNOWN_IPC",
    3: "EXTENSION_CHECK_IN_TIMEOUT",
    4: "SIGTERM_TIMEOUT",
    5: "ABANDONED",
    6: "SANDBOX_FILTERED_IPC",
    7: "FAST_LOGOUT",
    8: "UNMANAGED",
    9: "FAULT",
}

#: ``EXEC_EXIT_REASON_*`` of ``bsd/sys/reason.h``
_EXEC = {
    1: "BAD_MACHO",
    2: "SUGID_FAILURE",
    3: "ACTV_THREADSTATE",
    4: "STACK_ALLOC",
    5: "APPLE_STRING_INIT",
    6: "COPYOUT_STRINGS",
    7: "COPYOUT_DYNLINKER",
    8: "SECURITY_POLICY",
    9: "TASKGATED_OTHER",
    10: "FAIRPLAY_DECRYPT",
    11: "DECRYPT",
    12: "UPX",
    13: "NO32EXEC",
    14: "WRONG_PLATFORM",
    15: "MAIN_FD_ALLOC",
    16: "COPYOUT_ROSETTA",
    17: "SET_DYLD_INFO",
    18: "MACHINE_THREAD",
    19: "BAD_PSATTR",
    20: "NOX86EXEC",
    21: "MAP_EXEC_FAILURE",
}

#: What ``FBSProcessExceptionCodeDescription()`` of FrontBoardServices calls them; all but the
#: resource exclusion are also the ones ``+[RBSProcessExitStatus _nameForDomain:code:includeNumber:]``
#: of RunningBoardServices names in this namespace.
_SPRINGBOARD = {
    0x2BAD45EC: "Security Violation",
    0x8BADF00D: "Watchdog Violation",
    0xC00010FF: "Thermal Pressure",
    0xDEAD10CC: "Resource Exclusion",
    0xDEADFA11: "User Initiated Quit",
    0xFBFBFBFB: "Force Quit",
}

#: ``OS_REASON_LIBSYSTEM_CODE_*`` of ``libkern/os/reason_private.h``
_LIBSYSTEM = {
    1: "WORKLOOP_OWNERSHIP_LEAK",
    2: "FAULT",
    3: "SECINIT_INITIALIZER",
    4: "PTHREAD_CORRUPTION",
    5: "OS_LOG_FAULT",
}

#: What ``WatchdogExitReasonHelper.descriptionFromCode(_:)`` of CoreDiagnostics, which ReportCrash
#: asks, says of them. It holds no shorter name.
_WATCHDOG = {
    1: "monitoring timed out for service",
    2: "monitoring timed out for service without diags",
    3: "Terminated by Unblock framework for unrecoverable deadlock",
    4: "Terminated by Unblock framework for not recovering after hitting thread limit",
}

#: ``GUARD_REASON_*`` of ``bsd/sys/reason.h``
_GUARD = {
    1: "VNODE",
    2: "VIRT_MEMORY",
    3: "MACH_PORT",
    4: "EXCLAVES",
    5: "JIT",
}

#: What ``-[OSACrashReport decode_reasonRealityKit]`` of ReportCrash says of them
_REALITYKIT = {
    0: "RealityKit scene is too complex: SynchronizationComponent limit exceeded",
    1: "RealityKit scene is too complex: ModelComponent limit exceeded",
    2: "RealityKit scene is too complex: GroundingShadowComponent limit exceeded",
    3: "RealityKit scene is too complex: (Directional + Spot + Point) LightComponent limit exceeded",
    4: "RealityKit scene is too complex: AudioPlaybackController limit exceeded",
}

#: Names of the codes of each namespace which has any, by namespace
SUBCODES: Dict[int, Dict[int, str]] = {
    1: _JETSAM,
    2: _SIGNAL,
    3: _CODESIGNING,
    6: _DYLD,
    7: _LIBXPC,
    9: _EXEC,
    10: _SPRINGBOARD,
    18: _LIBSYSTEM,
    20: _WATCHDOG,
    23: _GUARD,
    38: _REALITYKIT,
}

#: As ``bsd/kern/kern_exit.c`` writes it into the panic string of a process which may not exit
_PANIC_EXIT_REASON = re.compile(r"exit reason namespace (\d+) subcode (0x[0-9a-fA-F]+)")


@dataclass(frozen=True)
class ExitReason:
    namespace: int
    subcode: int

    @property
    def namespace_name(self) -> Optional[str]:
        return NAMESPACES.get(self.namespace)

    @property
    def subcode_name(self) -> Optional[str]:
        return SUBCODES.get(self.namespace, {}).get(self.subcode)

    @classmethod
    def from_panic_string(cls, panic_string: str) -> Optional["ExitReason"]:
        """The exit reason a panic string tells of, ``None`` when it tells of none."""
        match = _PANIC_EXIT_REASON.search(panic_string)
        if match is None:
            return None
        return cls(namespace=int(match.group(1)), subcode=int(match.group(2), 16))

    def __str__(self) -> str:
        """Both names, the number standing in for a name which is not known."""
        namespace = self.namespace_name or f"namespace {self.namespace}"
        subcode = self.subcode_name or f"subcode 0x{self.subcode:x}"
        return f"{namespace}, {subcode}"
