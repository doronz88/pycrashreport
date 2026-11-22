import bisect
import dataclasses
import json
import os
import posixpath
import re
from collections import namedtuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from functools import cached_property
from io import StringIO
from typing import (
    Any,
    ClassVar,
    IO,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Tuple,
    Union,
)

from apple_symbols import (
    DeviceSupportSymbols,
    KernelSymbols,
    SymbolImage,
    find_device_support_symbols,
)
from rich.console import Console
from rich.text import Text

from pycrashreport.exit_reason import ExitReason

Frame = namedtuple("Frame", "image_name image_base image_offset symbol symbol_offset")
Register = namedtuple("Register", "name value")
KernelExtension = namedtuple("KernelExtension", "name version uuid start end")

#: Kinds of ``binaryImages`` entries a panic report locates its frames with
IMAGE_KIND_ABSOLUTE = "A"
IMAGE_KIND_SHARED_CACHE = "S"
IMAGE_KINDS_KERNEL = frozenset({"K", "T"})
#: The whole kernelcache as it is before sliding, which a stackshot locates its kernel frames with
IMAGE_KIND_UNSLID_KERNELCACHE = "U"
KERNEL_IMAGE_NAME = "kernel"
KERNELCACHE_IMAGE_NAME = "kernelcache"


STYLE_INCIDENT = "bold cyan"
STYLE_TIMESTAMP = "cyan"
STYLE_FILENAME = "dim cyan"
STYLE_LABEL = "bold"
STYLE_FAILURE = "bold red"
STYLE_DETAIL = "yellow"
STYLE_IMAGE = "green"
STYLE_SYMBOL = "bold yellow"
STYLE_ADDRESS = "blue"
STYLE_REGISTER = "cyan"
STYLE_REGISTER_CONTROL = "bold magenta"
STYLE_ZERO = "dim"
STYLE_IDENTIFIER = "dim"

#: Registers that say where execution was, set apart from the general purpose ones.
CONTROL_REGISTERS = frozenset({"pc", "lr", "sp", "fp", "rip", "rsp", "rbp"})

REGISTERS_PER_ROW = 4
REGISTER_CELL_WIDTH = 30


def _render_field(
    text: Text, label: str, value: object, style: Optional[str] = None
) -> None:
    """Append a line of a report: what it is, then its value."""
    text.append(f"{label}: ", style=STYLE_LABEL)
    text.append(f"{value}\n", style=style)


def _render_location(
    text: Text,
    image: Optional[str],
    address: int,
    symbol: Optional[str],
    symbol_offset: Optional[int],
    image_offset: Optional[int],
) -> None:
    """Append where a frame is: its image, its address, and its symbol or else its offset in the image."""
    text.append("[")
    text.append(image or "?", style=STYLE_IMAGE)
    text.append("] ")
    text.append(f"0x{address:x}", style=STYLE_ADDRESS)
    if symbol is not None:
        text.append(" (")
        text.append(symbol, style=STYLE_SYMBOL)
        text.append(f" + 0x{symbol_offset:x})")
    elif image_offset is not None:
        text.append(" (+ ")
        text.append(f"0x{image_offset:x}", style=STYLE_ADDRESS)
        text.append(")")
    text.append("\n")


def _to_ansi(text: Text) -> str:
    """Render to a string carrying ANSI colors, for callers that just ``print()`` a report.

    Colors are emitted whether or not the destination is a terminal, since a string cannot know
    where it will end up; ``NO_COLOR`` still drops them, leaving bold and dim.
    """
    buffer = StringIO()
    console = Console(
        file=buffer,
        force_terminal=True,
        color_system="standard",
        legacy_windows=False,
        highlight=False,
    )
    # soft_wrap: a register row or a frame is one line, never reflowed to some width
    console.print(text, soft_wrap=True, end="")
    return buffer.getvalue()


@dataclass(frozen=True)
class PanickedTask:
    address: int
    pages: int
    threads: int
    pid: int
    name: str


@dataclass(frozen=True)
class PanickedThread:
    address: int
    backtrace: int
    tid: int


@dataclass
class StackshotFrame:
    """One address of a call stack of a panic or a stackshot, innermost first."""

    address: int
    kernel: bool = False
    #: File name of the containing image when the symbols tell it, its UUID otherwise
    image: Optional[str] = None
    image_offset: Optional[int] = None
    symbol: Optional[str] = None
    symbol_offset: Optional[int] = None


@dataclass
class StackshotThread:
    """A thread of a process of a panic or a stackshot."""

    tid: int
    name: Optional[str] = None
    #: The kernel stack of a thread caught in the kernel comes on top of its user stack
    frames: List[StackshotFrame] = field(default_factory=list)
    #: Scheduling state, e.g. ``["TH_WAIT", "TH_UNINT"]``
    state: List[str] = field(default_factory=list)
    #: What a waiting thread waits on, when the report tells
    wait_info: Optional[str] = None
    #: Label of the dispatch queue the thread serves
    queue: Optional[str] = None
    base_priority: Optional[int] = None
    sched_priority: Optional[int] = None
    #: Time spent running, in microseconds
    user_usec: Optional[int] = None
    system_usec: Optional[int] = None
    #: Effective quality of service, e.g. ``QOS_CLASS_USER_INITIATED``
    qos: Optional[str] = None
    #: E.g. ``["kUser64_p", "kThreadIdleWorker"]``
    flags: List[str] = field(default_factory=list)
    #: The thread as the report gives it, for whatever has no field here
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @property
    def running(self) -> bool:
        return "TH_RUN" in self.state

    @property
    def kernel_frames(self) -> List[StackshotFrame]:
        return [frame for frame in self.frames if frame.kernel]

    @property
    def user_frames(self) -> List[StackshotFrame]:
        return [frame for frame in self.frames if not frame.kernel]


@dataclass
class StackshotProcess:
    """A process of a panic or a stackshot."""

    pid: int
    name: str
    threads: List[StackshotThread] = field(default_factory=list)
    parent_pid: Optional[int] = None
    user_id: Optional[int] = None
    group_id: Optional[int] = None
    #: E.g. ``["foreground", "isDirtyTracked", "sharedRegionSystem"]``
    flags: List[str] = field(default_factory=list)
    frontmost: bool = False
    resident_memory_bytes: Optional[int] = None
    #: Time its threads spent running, in seconds
    user_time: Optional[float] = None
    system_time: Optional[float] = None
    #: Seconds since it started
    uptime: Optional[float] = None
    #: The process as the report gives it, for whatever has no field here
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    def get_thread(self, tid: int) -> Optional[StackshotThread]:
        return next((thread for thread in self.threads if thread.tid == tid), None)


@dataclass
class MemoryStatus:
    """Memory of the system when a panic or a stackshot was taken."""

    page_size: Optional[int] = None
    #: Count of pages of each kind, e.g. ``active``, ``wired``, ``free``
    pages: Mapping[str, int] = field(default_factory=dict)
    memory_pressure: Optional[bool] = None
    compressor_size: Optional[int] = None
    compressions: Optional[int] = None
    decompressions: Optional[int] = None
    #: As the report gives it, for whatever has no field here
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)


#: Names from when only panics had processes
PanicFrame = StackshotFrame
PanicThread = StackshotThread
PanicProcess = StackshotProcess


@dataclass
class CrashThread:
    """A thread of the process of a userland crash report."""

    #: Its place among the threads of the report, which is how the report tells them apart
    index: int
    tid: Optional[int] = None
    name: Optional[str] = None
    #: Label of the dispatch queue the thread served
    queue: Optional[str] = None
    #: Whether this is the thread which crashed
    crashed: bool = False
    #: Innermost first
    frames: List[Frame] = field(default_factory=list)

    @property
    def description(self) -> str:
        parts = [str(self.index)]
        if self.tid is not None:
            parts.append(f"tid {self.tid}")
        if self.name:
            parts.append(self.name)
        if self.queue:
            parts.append(f"queue {self.queue}")
        return ", ".join(parts)


class BugType(Enum):
    WatchdogTimeout = "28"
    BasebandStats = "195"
    GPUEvent = "284"
    Sandbox = "187"
    TerminatingStackshot = "509"
    ServiceWatchdogTimeout = "29"
    Session = "179"
    LegacyStackshot = "188"
    MACorrelation = "197"
    iMessages = "189"
    log_power = "278"
    PowerLog = "powerlog"
    DuetKnowledgeCollector2 = "58"
    BridgeRestore = "83"
    LegacyJetsam = "198"
    ExcResource_385 = "385"
    Modem = "199"
    Stackshot = "288"
    SystemInformation = "system_profile"
    Jetsam_298 = "298"
    MemoryResource = "30"
    Bridge = "31"
    DifferentialPrivacy = "diff_privacy"
    FirmwareIntegrity = "32"
    CoreAnalytics_33 = "33"
    AutoBugCapture = "34"
    EfiFirmwareIntegrity = "35"
    SystemStats = "36"
    AnonSystemStats = "37"
    Crash_9 = "9"
    Jetsam_98 = "98"
    LDCM = "100"
    Panic_10 = "10"
    Spin = "11"
    CLTM = "101"
    Hang = "12"
    Panic_110 = "110"
    ConnectionFailure = "13"
    MessageTracer = "14"
    LowBattery = "120"
    Siri = "201"
    ShutdownStall = "17"
    Panic_210 = "210"
    SymptomsCPUUsage = "202"
    AssumptionViolation = "18"
    CoreHandwriting = "chw"
    IOMicroStackShot = "44"
    CoreAnalytics_211 = "211"
    SiriAppPrediction = "203"
    spin_45 = "45"
    PowerMicroStackshots = "220"
    BTMetadata = "212"
    SystemMemoryReset = "301"
    ResetCount = "115"
    AutoBugCapture_204 = "204"
    WifiCrashBinary = "221"
    MicroRunloopHang = "310"
    Rosetta = "213"
    glitchyspin = "302"
    System = "116"
    IOPowerSources = "141"
    PanicStats = "205"
    PowerLog_230 = "230"
    LongRunloopHang = "222"
    HomeProductsAnalytics = "311"
    DifferentialPrivacy_150 = "150"
    Rhodes = "214"
    ProactiveEventTrackerTransparency = "303"
    WiFi = "117"
    SymptomsCPUWakes = "142"
    SymptomsCPUUsageFatal = "206"
    Crash_109 = "109"
    ShortRunloopHang = "223"
    CoreHandwriting_231 = "231"
    ForceReset = "151"
    SiriAppSelection = "215"
    PrivateFederatedLearning = "304"
    Bluetooth = "118"
    SCPMotion = "143"
    HangSpin = "207"
    StepCount = "160"
    RTCTransparency = "224"
    DiagnosticRequest = "312"
    MemorySnapshot = "152"
    Rosetta_B = "216"
    AudioAccessory = "305"
    General = "119"
    HotSpotIOMicroSS = "144"
    GeoServicesTransparency = "233"
    MotionState = "161"
    AppStoreTransparency = "225"
    SiriSearchFeedback = "313"
    BearTrapReserved = "153"
    Portrait = "217"
    AWDMetricLog = "metriclog"
    SymptomsIO = "145"
    SubmissionReserved = "170"
    WifiCrash = "209"
    Natalies = "162"
    SecurityTransparency = "226"
    BiomeMapReduce = "234"
    MemoryGraph = "154"
    MultichannelAudio = "218"
    honeybee_payload = "146"
    MesaReserved = "171"
    WifiSensing = "235"
    SiriMiss = "163"
    ExcResourceThreads_227 = "227"
    TestA = "T01"
    NetworkUsage = "155"
    WifiReserved = "180"
    SiriActionPrediction = "219"
    honeybee_heartbeat = "147"
    ECCEvent = "172"
    KeyTransparency = "236"
    SubDiagHeartBeat = "164"
    ThirdPartyHang = "228"
    OSFault = "308"
    CoreTime = "156"
    WifiDriverReserved = "181"
    Crash_309 = "309"
    honeybee_issue = "148"
    CellularPerfReserved = "173"
    TestB = "T02"
    StorageStatus = "165"
    SiriNotificationTransparency = "229"
    TestC = "T03"
    CPUMicroSS = "157"
    AccessoryUpdate = "182"
    xprotect = "20"
    MultitouchFirmware = "149"
    MicroStackshot = "174"
    AppLaunchDiagnostics = "238"
    KeyboardAccuracy = "166"
    GPURestart = "21"
    FaceTime = "191"
    DuetKnowledgeCollector = "158"
    OTASUpdate = "183"
    ExcResourceThreads_327 = "327"
    ExcResource_22 = "22"
    DuetDB = "175"
    ThirdPartyHangDeveloper = "328"
    PrivacySettings = "167"
    GasGauge = "192"
    MicroStackShots = "23"
    BasebandCrash = "159"
    GPURestart_184 = "184"
    SystemWatchdogCrash = "409"
    FlashStatus = "176"
    SleepWakeFailure = "24"
    CarouselEvent = "168"
    AggregateD = "193"
    WakeupsMonitorViolation = "25"
    DifferentialPrivacy_50 = "50"
    ExcResource_185 = "185"
    UIAutomation = "177"
    ping = "26"
    SiriTransaction = "169"
    SURestore = "194"
    KtraceStackshot = "186"
    WirelessDiagnostics = "27"
    PowerLogLite = "178"
    SKAdNetworkAnalytics = "237"
    HangWorkflowResponsiveness = "239"
    AMTStreamingStallNetworkDiagnostics = "241"
    CompositorClientHang = "243"
    AVConference = "240"
    HotStopAppLaunchLog = "248"


class CrashReportBase:
    """A crash report of any bug type. Subclasses parse what their own report format carries."""

    #: Bug types a subclass parses. Listing them here is all it takes to be picked for them.
    BUG_TYPES: ClassVar[tuple] = ()

    _parsers: ClassVar[dict] = {}

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        for bug_type in cls.BUG_TYPES:
            CrashReportBase._parsers[bug_type.value] = cls

    @staticmethod
    def parser_for(bug_type: str) -> "type[CrashReportBase]":
        """Class parsing reports of the given raw bug type, the base class when none is dedicated."""
        return CrashReportBase._parsers.get(bug_type, CrashReportBase)

    def __init__(
        self,
        metadata: Mapping[str, Any],
        data: str,
        filename: Optional[str] = None,
    ) -> None:
        self.filename = filename
        self._data = data
        self._metadata = metadata
        self._parse()

    def _parse(self):
        self._is_json = False
        try:
            modified_data = self._data
            if "\n  \n" in modified_data:
                modified_data, rest = modified_data.split("\n  \n", 1)
                rest = '",' + rest.split('",', 1)[1]
                modified_data += rest
            self._data = json.loads(modified_data)
            self._is_json = True
        except json.decoder.JSONDecodeError:
            pass

    @cached_property
    def bug_type(self) -> BugType:
        return BugType(self.bug_type_str)

    @cached_property
    def bug_type_str(self) -> str:
        return self._metadata["bug_type"]

    @cached_property
    def incident_id(self) -> Optional[str]:
        return self._metadata.get("incident_id")

    @cached_property
    def timestamp(self) -> datetime:
        timestamp = self._metadata.get("timestamp")
        timestamp_without_timezone = timestamp.rsplit(" ", 1)[0]
        return datetime.strptime(timestamp_without_timezone, "%Y-%m-%d %H:%M:%S.%f")

    @cached_property
    def name(self) -> str:
        return self._metadata.get("name")

    @property
    def product_type(self) -> Optional[str]:
        """Model of the device the report came from, e.g. ``iPhone17,3``, when the report tells."""
        return None

    @property
    def build_version(self) -> Optional[str]:
        """Build of the OS the report came from, e.g. ``23E246``, when the report tells."""
        return None

    @cached_property
    def device_support_symbols(self) -> Optional[DeviceSupportSymbols]:
        """Symbols naming the userland frames the report left unnamed.

        Defaults to the Xcode DeviceSupport of the device and build the report came from, when
        this host has it. Assign other symbols, or ``None`` for none, before reading any frames.
        """
        if not self.product_type or not self.build_version:
            return None
        root = find_device_support_symbols(self.product_type, self.build_version)
        if root is None:
            return None
        try:
            return DeviceSupportSymbols.load(root)
        except OSError:
            return None

    def _symbolicate_user_frame(
        self, image: SymbolImage, offset: int, innermost: bool
    ) -> Optional[tuple]:
        """Name the function at ``offset`` of a userland image, with the offset from its start."""
        symbols = self.device_support_symbols
        if symbols is None:
            return None
        # All but the innermost frame hold a return address, which may already belong to the
        # next function when the call never returns. Look up the call instruction instead.
        delta = 0 if innermost else 1
        symbol = symbols.symbolicate(image, image.vmaddr + offset - delta)
        if symbol is None:
            return None
        return symbol[0], symbol[1] + delta

    def _render_details(self, text: Text) -> None:
        """Append what follows the summary. Nothing, unless a subclass knows the format."""

    def __rich__(self) -> Text:
        text = Text()
        text.append(f"{self.incident_id} ", style=STYLE_INCIDENT)
        text.append(f"{self.timestamp}\n", style=STYLE_TIMESTAMP)
        text.append(f"{self.filename or ''}\n\n", style=STYLE_FILENAME)
        self._render_details(text)
        return text

    def __repr__(self):
        source = (
            f"FILENAME:{posixpath.basename(self.filename)} " if self.filename else ""
        )
        return f"<{self.__class__} {source}TIMESTAMP:{self.timestamp}>"

    def __str__(self):
        return _to_ansi(self.__rich__())


class ProcessesReport(CrashReportBase):
    """A report holding several processes, which a subclass reads into ``processes``."""

    processes: List[Any]

    def get_process(self, pid: int) -> Optional[Any]:
        return next((found for found in self.processes if found.pid == pid), None)

    def find_processes(self, process: str) -> List[Any]:
        """Get the processes of the report with the given name, or the one with the given pid."""
        if process.isdigit():
            return [found for found in self.processes if found.pid == int(process)]
        return [found for found in self.processes if found.name == process]

    def render_processes(self, processes: Iterable[Any]) -> Text:
        """Render the call stacks of the given processes."""
        raise NotImplementedError


class UserModeCrashReport(CrashReportBase):
    BUG_TYPES = (
        BugType.Crash_109,
        BugType.Crash_309,
        BugType.ExcResourceThreads_327,
        BugType.ExcResource_385,
    )

    def _parse_text_field(self, name: str) -> Optional[str]:
        """A field of a report in the text format, ``None`` for one in the JSON format."""
        return None if self._is_json else self._parse_field(name)

    def _text_section(self, heading: str) -> Iterator[str]:
        """The lines below the one starting with ``heading``, up to the first empty one."""
        lines = iter(self._data.split("\n"))
        for line in lines:
            if line.startswith(heading):
                break
        for line in lines:
            if not line.strip():
                return
            yield line

    def _parse_field(self, name: str) -> str:
        name += ":"
        for line in self._data.split("\n"):
            if line.startswith(name):
                field = line.split(name, 1)[1]
                field = field.strip()
                return field

    @property
    def product_type(self) -> Optional[str]:
        if self._is_json:
            return self._data.get("modelCode")
        return self._parse_field("Hardware Model")

    @property
    def build_version(self) -> Optional[str]:
        if self._is_json:
            return (self._data.get("osVersion") or {}).get("build")
        match = re.search(r"\(([^)]+)\)", self._parse_field("OS Version") or "")
        return match.group(1) if match else None

    @cached_property
    def faulting_thread(self) -> int:
        if self._is_json:
            return self._data["faultingThread"]
        else:
            return int(self._parse_field("Triggered by Thread"))

    def _json_frames(self, thread: Mapping[str, Any]) -> List[Frame]:
        """The call stack of a thread of a report in the JSON format, innermost first."""
        result: List[Frame] = []
        images = self._data["usedImages"]
        for frame in thread.get("frames") or self._json_resume_frame(thread):
            image = images[frame["imageIndex"]]
            symbol = frame.get("symbol")
            symbol_offset = frame.get("symbolLocation")
            if symbol is None:
                # the device names what it can; the rest is up to the host's symbols
                named = self._symbolicate_json_frame(image, frame, innermost=not result)
                if named is not None:
                    symbol, symbol_offset = named
            result.append(
                Frame(
                    image_name=image.get("path"),
                    image_base=image.get("base"),
                    symbol=symbol,
                    image_offset=frame.get("imageOffset"),
                    symbol_offset=symbol_offset,
                )
            )
        return result

    def _json_resume_frame(self, thread: Mapping[str, Any]) -> List[Mapping[str, Any]]:
        """Where a thread the report gives no call stack of would resume, as its only frame.

        Such a thread has no stack to unwind: an idle worker of a dispatch queue, for one, is
        parked in the kernel and resumes at the start of ``start_wqthread``.
        """
        state = thread.get("threadState") or {}
        pc = (state.get("pc") or state.get("rip") or {}).get("value")
        if not pc:
            return []
        for index, image in enumerate(self._data["usedImages"]):
            base = image.get("base")
            if base is not None and base <= pc < base + (image.get("size") or 0):
                return [{"imageIndex": index, "imageOffset": pc - base}]
        return []

    @cached_property
    def threads(self) -> List[CrashThread]:
        """Every thread of the process, with its call stack. Empty for a report in the text format."""
        if not self._is_json:
            return []
        return [
            CrashThread(
                index=index,
                tid=thread.get("id"),
                name=thread.get("name"),
                queue=thread.get("queue"),
                crashed=bool(thread.get("triggered")),
                # the stack of the faulting thread is `frames`, and is not read twice
                frames=(
                    self.frames
                    if index == self.faulting_thread
                    else self._json_frames(thread)
                ),
            )
            for index, thread in enumerate(self._data.get("threads") or [])
        ]

    def _json_field(self, name: str) -> Any:
        return self._data.get(name) if self._is_json else None

    @property
    def process_name(self) -> Optional[str]:
        return self._json_field("procName") or self._parse_text_field("Process")

    @property
    def pid(self) -> Optional[int]:
        return self._json_field("pid")

    @property
    def process_path(self) -> Optional[str]:
        return self._json_field("procPath") or self._parse_text_field("Path")

    @property
    def parent_name(self) -> Optional[str]:
        return self._json_field("parentProc")

    @property
    def parent_pid(self) -> Optional[int]:
        return self._json_field("parentPid")

    @property
    def signal(self) -> Optional[str]:
        """The signal the exception was delivered as, e.g. ``SIGABRT``."""
        return (self._json_field("exception") or {}).get("signal")

    @property
    def exception_codes(self) -> Optional[str]:
        if self._is_json:
            return self._data["exception"].get("codes")
        return self._parse_text_field("Exception Codes")

    @property
    def termination(self) -> Optional[Mapping[str, Any]]:
        """Why the process ended as the report tells it: ``namespace``, ``code``, ``indicator``,
        and ``byProc`` with ``byPid`` for the process which ended it."""
        return self._json_field("termination")

    @property
    def termination_reason(self) -> Optional[str]:
        """Why the process ended and who ended it, on one line."""
        termination = self.termination
        if not termination:
            return self._parse_text_field("Termination Reason")
        parts = [
            str(termination[key])
            for key in ("namespace", "indicator")
            if termination.get(key)
        ]
        if not termination.get("indicator") and termination.get("code") is not None:
            parts.append(f"code {termination['code']}")
        if termination.get("byProc"):
            by = f"by {termination['byProc']}"
            if termination.get("byPid") is not None:
                by += f" (pid {termination['byPid']})"
            parts.append(by)
        return ", ".join(parts) or None

    @cached_property
    def frames(self) -> List[Frame]:
        result = []
        if self._is_json:
            return self._json_frames(self._data["threads"][self.faulting_thread])
        else:
            for line in self._text_section(f"Thread {self.faulting_thread} Crashed:"):
                splitted = line.split()
                assert splitted[-2] == "+"
                image_base = splitted[-3]
                if image_base.startswith("0x"):
                    result.append(
                        Frame(
                            image_name=splitted[1],
                            image_base=int(image_base, 16),
                            symbol=None,
                            image_offset=int(splitted[-1]),
                            symbol_offset=None,
                        )
                    )
                else:
                    # symbolicated
                    result.append(
                        Frame(
                            image_name=splitted[1],
                            image_base=None,
                            symbol=image_base,
                            image_offset=None,
                            symbol_offset=int(splitted[-1]),
                        )
                    )

        return result

    def _symbolicate_json_frame(
        self, image: Mapping[str, Any], frame: Mapping[str, Any], innermost: bool
    ) -> Optional[tuple]:
        symbols = self.device_support_symbols
        offset = frame.get("imageOffset")
        if symbols is None or offset is None or not image.get("uuid"):
            return None
        symbol_image = symbols.image_by_uuid(image["uuid"])
        if symbol_image is None:
            return None
        return self._symbolicate_user_frame(symbol_image, offset, innermost)

    @cached_property
    def registers(self) -> List[Register]:
        result = []
        if self._is_json:
            thread_index = self._data["faultingThread"]
            thread_state = self._data["threads"][thread_index]["threadState"]

            for i, (name, value) in enumerate(thread_state.items()):
                if name == "x":
                    for j, reg_x in enumerate(value):
                        result.append(Register(name=f"x{j}", value=reg_x["value"]))
                else:
                    if isinstance(value, dict):
                        result.append(Register(name=name, value=value["value"]))
        else:
            for line in self._text_section(
                f"Thread {self.faulting_thread} crashed with ARM Thread State"
            ):
                splitted = line.split()
                for i in range(0, len(splitted), 2):
                    register_name = splitted[i]
                    if not register_name.endswith(":"):
                        break
                    result.append(
                        Register(
                            name=register_name[:-1], value=int(splitted[i + 1], 16)
                        )
                    )

        return result

    @cached_property
    def exception_type(self) -> Optional[str]:
        if self._is_json:
            return self._data["exception"].get("type")
        else:
            return self._parse_field("Exception Type")

    @cached_property
    def exception_subtype(self) -> Optional[str]:
        if self._is_json:
            return self._data["exception"].get("subtype")
        else:
            return self._parse_field("Exception Subtype")

    @cached_property
    def application_specific_information(self) -> Optional[str]:
        if self._is_json:
            return self._data.get("asi")
        lines = self._text_section("Application Specific Information:")
        return "\n".join(line.strip() for line in lines) or None

    def _render_details(self, text: Text) -> None:
        if self.process_name:
            text.append("Process: ", style=STYLE_LABEL)
            text.append(self.process_name, style=STYLE_IMAGE)
            if self.pid is not None:
                text.append(f" (pid {self.pid})")
            if self.process_path:
                text.append(f" {self.process_path}", style=STYLE_IDENTIFIER)
            text.append("\n")
        if self.parent_name:
            text.append("Parent: ", style=STYLE_LABEL)
            text.append(f"{self.parent_name} (pid {self.parent_pid})\n")
        if self.product_type:
            text.append("Device: ", style=STYLE_LABEL)
            text.append(f"{self.product_type} ({self.build_version})\n")
        text.append("Exception: ", style=STYLE_LABEL)
        text.append(str(self.exception_type), style=STYLE_FAILURE)
        if self.signal:
            text.append(f" ({self.signal})", style=STYLE_FAILURE)
        text.append("\n")
        if self.exception_subtype:
            _render_field(
                text, "Exception Subtype", self.exception_subtype, STYLE_DETAIL
            )
        if self.exception_codes:
            _render_field(text, "Exception Codes", self.exception_codes, STYLE_DETAIL)
        if self.termination_reason:
            _render_field(text, "Termination", self.termination_reason, STYLE_DETAIL)
        crashed = next((thread for thread in self.threads if thread.crashed), None)
        if crashed is not None:
            _render_field(text, "Crashed thread", crashed.description)
        if self.application_specific_information:
            text.append("Application Specific Information: ", style=STYLE_LABEL)
            text.append(str(self.application_specific_information), style=STYLE_DETAIL)

        text.append("\n")

        text.append("Registers:", style=STYLE_LABEL)
        for i, register in enumerate(self.registers):
            if i % REGISTERS_PER_ROW == 0:
                text.append("\n")
            self._render_register(text, register)

        text.append("\n\n")

        text.append("Frames:\n", style=STYLE_LABEL)
        for frame in self.frames:
            self._render_frame(text, frame)

    def render_threads(self) -> Text:
        """Render the call stack of every thread of the process."""
        text = Text()
        for thread in self.threads:
            text.append("Thread: ", style=STYLE_LABEL)
            text.append(thread.description)
            if thread.crashed:
                text.append(" (crashed)", style=STYLE_FAILURE)
            text.append("\n")
            for frame in thread.frames:
                self._render_frame(text, frame)
        return text

    @staticmethod
    def _render_register(text: Text, register: Register) -> None:
        value = f"0x{register.value:016x}"
        # right-aligned in a fixed cell, so the rows line up into columns
        cell = f"{register.name} = {value} "
        text.append(" " * (REGISTER_CELL_WIDTH - len(cell)))
        text.append(
            register.name,
            style=(
                STYLE_REGISTER_CONTROL
                if register.name in CONTROL_REGISTERS
                else STYLE_REGISTER
            ),
        )
        text.append(" = ")
        text.append(value, style=STYLE_ZERO if register.value == 0 else None)
        text.append(" ")

    @staticmethod
    def _render_frame(text: Text, frame: Frame) -> None:
        text.append("\t[")
        text.append(str(frame.image_name), style=STYLE_IMAGE)
        text.append("] ")
        text.append(
            "_HEADER" if frame.image_base is None else f"0x{frame.image_base:x}",
            style=STYLE_ADDRESS,
        )
        if frame.image_offset:
            text.append(" + ")
            text.append(f"0x{frame.image_offset:x}", style=STYLE_ADDRESS)
        if frame.symbol is not None:
            text.append(" (")
            text.append(frame.symbol, style=STYLE_SYMBOL)
            text.append(f" + 0x{frame.symbol_offset:x})")
        text.append("\n")


class StackshotReportBase(ProcessesReport):
    """A report carrying a stackshot: the processes of the system and the stacks of their threads."""

    #: Symbols naming the kernel frames, which need the kernelcache the device ran. Assign them
    #: before reading any frames.
    kernel_symbols: Optional[KernelSymbols] = None

    def _report_field(self, name: str) -> Any:
        if self._is_json and isinstance(self._data, dict):
            return self._data.get(name)
        return None

    @property
    def product_type(self) -> Optional[str]:
        return self._report_field("product")

    @property
    def build_version(self) -> Optional[str]:
        # "iPhone OS 16.2 (20C65)"
        match = re.search(r"\(([^)]+)\)\s*$", self._report_field("build") or "")
        return match.group(1) if match else None

    @property
    def _reported_kernel_images(self) -> dict:
        """Names the report itself gives to kernel images, by their lowercase UUID."""
        return {}

    def _kernel_frame(
        self, uuid: str, base: int, offset: int, innermost: bool
    ) -> StackshotFrame:
        frame = StackshotFrame(
            address=base + offset,
            kernel=True,
            image=self._reported_kernel_images.get(uuid.lower(), uuid),
            image_offset=offset,
        )
        if self.kernel_symbols is None:
            return frame
        image = self.kernel_symbols.image_by_uuid(uuid)
        if image is None:
            return frame
        frame.image = image.name
        # the report gives where `__TEXT_EXEC` of a kernel image got loaded
        self._name_kernel_frame(frame, image.text_exec + offset, innermost)
        return frame

    def _name_kernel_frame(
        self, frame: StackshotFrame, address: int, innermost: bool
    ) -> None:
        """Name the function at the unslid ``address`` of the kernelcache."""
        # All but the innermost frame hold a return address: look up the call instruction instead
        delta = 0 if innermost else 1
        symbol = self.kernel_symbols.symbolicate(address - delta)
        if symbol is not None:
            frame.symbol = symbol[0]
            frame.symbol_offset = symbol[1] + delta

    @cached_property
    def _kernel_images_by_address(self) -> tuple:
        """The images of the kernel symbols in the order of their code, after where each starts."""
        images = sorted(self.kernel_symbols.images, key=lambda image: image.text_exec)
        return [image.text_exec for image in images], images

    def _kernelcache_frame(self, address: int, innermost: bool) -> StackshotFrame:
        """A frame located by its unslid address in the kernelcache, not by one of its images."""
        frame = StackshotFrame(
            address=address, kernel=True, image=KERNELCACHE_IMAGE_NAME
        )
        if self.kernel_symbols is None:
            return frame
        # the code of the images of a kernelcache is laid out back to back, so an address
        # belongs to the image whose code starts closest below it
        starts, images = self._kernel_images_by_address
        index = bisect.bisect_right(starts, address)
        if index:
            frame.image = images[index - 1].name
            frame.image_offset = address - images[index - 1].text_exec
        self._name_kernel_frame(frame, address, innermost)
        return frame

    @cached_property
    def _system_shared_caches(self) -> Optional[frozenset]:
        """UUIDs of the shared cache the system runs on, ``None`` when the report does not tell.

        DriverKit processes run on a shared cache of their own, which DeviceSupport does not
        hold. A process says which kind it uses, so the caches of the ones on the system's
        are the system's.
        """
        images = self._report_field("binaryImages") or []
        told = False
        caches = set()
        for process in (self._report_field("processByPid") or {}).values():
            flags = process.get("flags") or []
            told = told or any(flag.startswith("sharedRegion") for flag in flags)
            if "sharedRegionSystem" not in flags:
                continue
            for thread in (process.get("threadById") or {}).values():
                for index, _offset in thread.get("userFrames") or []:
                    if (
                        0 <= index < len(images)
                        and images[index][2] == IMAGE_KIND_SHARED_CACHE
                    ):
                        caches.add(images[index][0].lower())
        return frozenset(caches) if told else None

    def _user_frame(
        self, uuid: str, base: int, kind: str, offset: int, innermost: bool
    ) -> StackshotFrame:
        frame = StackshotFrame(address=base + offset, image=uuid, image_offset=offset)
        symbols = self.device_support_symbols
        if symbols is None:
            return frame
        if kind == IMAGE_KIND_SHARED_CACHE:
            system_caches = self._system_shared_caches
            if system_caches is not None and uuid.lower() not in system_caches:
                return frame
            # located by its offset in the whole shared cache, whose UUID this is
            cache_base = symbols.shared_cache_base
            image = (
                symbols.image_by_address(cache_base + offset)
                if cache_base is not None
                else None
            )
            if image is not None:
                offset = cache_base + offset - image.vmaddr
        else:
            image = symbols.image_by_uuid(uuid)
        if image is None:
            return frame
        frame.image = image.name
        frame.image_offset = offset
        symbol = self._symbolicate_user_frame(image, offset, innermost)
        if symbol is not None:
            frame.symbol, frame.symbol_offset = symbol
        return frame

    def _frames(self, thread: Mapping[str, Any]) -> List[StackshotFrame]:
        images = self._report_field("binaryImages") or []
        frames: List[StackshotFrame] = []
        for key in ("kernelFrames", "userFrames"):
            for index, offset in thread.get(key) or []:
                if not 0 <= index < len(images):
                    continue
                uuid, base, kind = images[index][:3]
                if kind == IMAGE_KIND_ABSOLUTE:
                    if offset:
                        frames.append(
                            StackshotFrame(address=offset, kernel=key == "kernelFrames")
                        )
                elif kind in IMAGE_KINDS_KERNEL:
                    frames.append(self._kernel_frame(uuid, base, offset, not frames))
                elif kind == IMAGE_KIND_UNSLID_KERNELCACHE:
                    frames.append(self._kernelcache_frame(base + offset, not frames))
                else:
                    frame = self._user_frame(uuid, base, kind, offset, not frames)
                    # a kernel stack also goes through images which are not of the kernelcache
                    frame.kernel = key == "kernelFrames"
                    frames.append(frame)
        return frames

    @staticmethod
    def _wait_info(process: Mapping[str, Any]) -> dict:
        """What the waiting threads of a process wait on, by their tid."""
        result = {}
        for entry in process.get("waitInfo") or []:
            match = re.fullmatch(r"thread (\d+): (.+)", entry)
            if match:
                result[int(match.group(1))] = match.group(2)
        return result

    @cached_property
    def processes(self) -> List[StackshotProcess]:
        """Every process the report holds, with the call stack of each of its threads."""
        result = []
        for pid, process in (self._report_field("processByPid") or {}).items():
            stackshot_process = StackshotProcess(
                pid=int(pid),
                name=process.get("procname") or "",
                parent_pid=process.get("parentPid"),
                user_id=process.get("userID"),
                group_id=process.get("groupID"),
                flags=list(process.get("flags") or []),
                frontmost=bool(process.get("frontmost")),
                resident_memory_bytes=process.get("residentMemoryBytes"),
                user_time=process.get("userTimeTask"),
                system_time=process.get("systemTimeTask"),
                uptime=process.get("processUptime"),
                raw=process,
            )
            wait_info = self._wait_info(process)
            for tid, thread in (process.get("threadById") or {}).items():
                stackshot_process.threads.append(
                    StackshotThread(
                        tid=int(tid),
                        name=thread.get("name"),
                        frames=self._frames(thread),
                        state=list(thread.get("state") or []),
                        wait_info=wait_info.get(int(tid)),
                        queue=thread.get("dispatch_queue_label"),
                        base_priority=thread.get("basePriority"),
                        sched_priority=thread.get("schedPriority"),
                        user_usec=thread.get("user_usec"),
                        system_usec=thread.get("system_usec"),
                        qos=thread.get("qosEffective"),
                        flags=list(thread.get("snapshotFlags") or []),
                        raw=thread,
                    )
                )
            result.append(stackshot_process)
        return result

    @cached_property
    def memory_status(self) -> Optional[MemoryStatus]:
        status = self._report_field("memoryStatus")
        if not status:
            return None
        return MemoryStatus(
            page_size=status.get("pageSize"),
            pages=dict(status.get("memoryPages") or {}),
            memory_pressure=status.get("memoryPressure"),
            compressor_size=status.get("compressorSize"),
            compressions=status.get("compressions"),
            decompressions=status.get("decompressions"),
            raw=status,
        )

    @property
    def running_processes(self) -> List[StackshotProcess]:
        """The processes with a thread on a CPU, each with those threads only."""
        result = []
        for process in self.processes:
            threads = [thread for thread in process.threads if thread.running]
            if threads:
                result.append(dataclasses.replace(process, threads=threads))
        return result

    def _thread_marker(self, thread: StackshotThread) -> Optional[str]:
        """What sets a thread apart from the others of the report, if anything."""
        return None

    def render_processes(self, processes: Iterable[StackshotProcess]) -> Text:
        """Render the call stack of every thread of the given processes."""
        text = Text()
        for process in processes:
            text.append("Process: ", style=STYLE_LABEL)
            text.append(process.name or "?", style=STYLE_IMAGE)
            text.append(f" (pid {process.pid}, {len(process.threads)} threads)\n")
            for thread in process.threads:
                text.append("\tThread: ", style=STYLE_LABEL)
                text.append(f"tid {thread.tid}")
                if thread.name:
                    text.append(f" {thread.name}", style=STYLE_DETAIL)
                marker = self._thread_marker(thread)
                if marker:
                    text.append(f" ({marker})", style=STYLE_FAILURE)
                if thread.state:
                    text.append(f" [{', '.join(thread.state)}]", style=STYLE_IDENTIFIER)
                text.append("\n")
                if thread.queue:
                    _render_field(text, "\t\tQueue", thread.queue, STYLE_DETAIL)
                if thread.wait_info:
                    _render_field(text, "\t\tWaiting", thread.wait_info, STYLE_DETAIL)
                self._render_thread_accounting(text, thread)
                for frame in thread.frames:
                    self._render_frame(text, frame, indent="\t\t")
        return text

    @staticmethod
    def _render_thread_accounting(text: Text, thread: StackshotThread) -> None:
        """Append the priority of a thread and the time it ran, as far as the report tells."""
        parts = []
        if thread.sched_priority is not None:
            parts.append(f"priority {thread.sched_priority}")
            if thread.base_priority not in (None, thread.sched_priority):
                parts[-1] += f" (base {thread.base_priority})"
        if thread.user_usec is not None:
            parts.append(f"user {thread.user_usec} usec")
        if thread.system_usec is not None:
            parts.append(f"system {thread.system_usec} usec")
        if parts:
            text.append(f"\t\t{', '.join(parts)}\n", style=STYLE_IDENTIFIER)

    @staticmethod
    def _render_frame(text: Text, frame: StackshotFrame, indent: str = "\t") -> None:
        text.append(indent)
        text.append("kernel" if frame.kernel else "user  ", style=STYLE_IDENTIFIER)
        text.append(" ")
        _render_location(
            text,
            frame.image,
            frame.address,
            frame.symbol,
            frame.symbol_offset,
            frame.image_offset,
        )


class StackshotCrashReport(StackshotReportBase):
    """A stackshot of a running system, as sysdiagnose takes."""

    BUG_TYPES = (BugType.Stackshot,)

    @cached_property
    def reason(self) -> Optional[str]:
        """Why the stackshot was taken."""
        return self._report_field("reason")

    @cached_property
    def notes(self) -> List[str]:
        return list(self._report_field("notes") or [])

    @cached_property
    def kernel_version(self) -> Optional[str]:
        return self._report_field("kernel")

    @cached_property
    def frontmost_pids(self) -> List[int]:
        return list(self._report_field("frontmostPids") or [])

    @property
    def frontmost_processes(self) -> List[StackshotProcess]:
        return [found for found in self.processes if found.pid in self.frontmost_pids]

    def _render_details(self, text: Text) -> None:
        # read off the report itself: listing `processes` names every frame of every thread
        processes = self._report_field("processByPid") or {}
        if self.reason:
            _render_field(text, "Reason", self.reason, STYLE_FAILURE)
        for note in self.notes:
            _render_field(text, "Note", note, STYLE_DETAIL)
        if self.product_type:
            text.append("Device: ", style=STYLE_LABEL)
            text.append(f"{self.product_type}, {self._report_field('build')}\n")
        if self.kernel_version:
            _render_field(text, "Kernel", self.kernel_version)
        threads = sum(
            len(process.get("threadById") or {}) for process in processes.values()
        )
        memory = self.memory_status
        if memory is not None and memory.pages:
            text.append("Memory pages: ", style=STYLE_LABEL)
            text.append(
                ", ".join(f"{name} {count}" for name, count in memory.pages.items())
            )
            if memory.page_size:
                text.append(f" ({memory.page_size} bytes each)")
            text.append("\n")
        text.append("Processes: ", style=STYLE_LABEL)
        text.append(f"{len(processes)} ({threads} threads)\n")
        for pid in self.frontmost_pids:
            text.append("Frontmost: ", style=STYLE_LABEL)
            name = (processes.get(str(pid)) or {}).get("procname") or "?"
            text.append(name, style=STYLE_IMAGE)
            text.append(f" (pid {pid})\n")
        if processes:
            text.append(
                "\tCall stacks are printed for the processes asked for, by name or pid.\n",
                style=STYLE_IDENTIFIER,
            )


class KernelModeCrashReport(StackshotReportBase):
    BUG_TYPES = (BugType.ForceReset, BugType.Panic_210)

    def _parse(self):
        super()._parse()
        self._panic_text = ""
        if self._is_json and isinstance(self._data, dict):
            self._panic_text = (
                self._data.get("string") or self._data.get("panicString") or ""
            )
        elif isinstance(self._data, str):
            self._panic_text = self._data

    @cached_property
    def _reported_kernel_images(self) -> dict:
        names = {}
        if self.kernel_uuid:
            names[self.kernel_uuid.lower()] = KERNEL_IMAGE_NAME
        for extension in self.kernel_extensions_in_backtrace:
            names[extension.uuid.lower()] = extension.name
        return names

    @cached_property
    def panicked_thread_frames(self) -> List[StackshotFrame]:
        """Call stack of the thread which panicked, empty when the report does not hold it."""
        if self.panicked_thread is None:
            return []
        for process in self.processes:
            for thread in process.threads:
                if thread.tid == self.panicked_thread.tid:
                    return thread.frames
        return []

    def _panic_lines(self) -> List[str]:
        return self._panic_text.splitlines()

    def _line_value(self, prefix: str) -> Optional[str]:
        for line in self._panic_lines():
            if line.startswith(prefix):
                return line.split(":", 1)[1].strip()
        return None

    @cached_property
    def panic_string(self) -> str:
        lines = self._panic_lines()
        if not lines:
            return ""
        first_line = lines[0]
        match = re.match(r"panic\(cpu \d+ caller 0x[0-9a-fA-F]+\): (.+)", first_line)
        if match:
            return match.group(1)
        return first_line

    @cached_property
    def exit_reason(self) -> Optional[ExitReason]:
        """Why the process ended whose exit made the kernel panic, when that is what happened."""
        return ExitReason.from_panic_string(self.panic_string)

    @cached_property
    def panic_caller(self) -> Optional[int]:
        lines = self._panic_lines()
        if not lines:
            return None
        first_line = lines[0]
        match = re.search(r" caller (0x[0-9a-fA-F]+)\):", first_line)
        if match is None:
            return None
        return int(match.group(1), 16)

    @cached_property
    def debugger_message(self) -> Optional[str]:
        return self._line_value("Debugger message")

    @cached_property
    def memory_id(self) -> Optional[int]:
        value = self._line_value("Memory ID")
        return int(value, 16) if value is not None else None

    @cached_property
    def os_release_type(self) -> Optional[str]:
        return self._line_value("OS release type")

    @cached_property
    def os_version(self) -> Optional[str]:
        return self._line_value("OS version")

    @cached_property
    def kernel_version(self) -> Optional[str]:
        return self._line_value("Kernel version")

    @cached_property
    def fileset_kernelcache_uuid(self) -> Optional[str]:
        return self._line_value("Fileset Kernelcache UUID")

    @cached_property
    def kernel_uuid(self) -> Optional[str]:
        return self._line_value("Kernel UUID")

    @cached_property
    def boot_session_uuid(self) -> Optional[str]:
        return self._line_value("Boot session UUID")

    @cached_property
    def iboot_version(self) -> Optional[str]:
        return self._line_value("iBoot version")

    @cached_property
    def secure_boot(self) -> Optional[bool]:
        value = self._line_value("secure boot?")
        if value is None:
            return None
        return value == "YES"

    @cached_property
    def roots_installed(self) -> Optional[int]:
        value = self._line_value("roots installed")
        return int(value) if value is not None else None

    @cached_property
    def paniclog_version(self) -> Optional[int]:
        value = self._line_value("Paniclog version")
        return int(value) if value is not None else None

    @cached_property
    def panicked_task(self) -> Optional[PanickedTask]:
        for line in self._panic_lines():
            match = re.match(
                r"Panicked task (0x[0-9a-fA-F]+): (\d+) pages, (\d+) threads: pid (\d+): (.+)",
                line,
            )
            if match:
                return PanickedTask(
                    address=int(match.group(1), 16),
                    pages=int(match.group(2)),
                    threads=int(match.group(3)),
                    pid=int(match.group(4)),
                    name=match.group(5),
                )
        return None

    @cached_property
    def panicked_thread(self) -> Optional[PanickedThread]:
        for line in self._panic_lines():
            match = re.match(
                r"Panicked thread: (0x[0-9a-fA-F]+), backtrace: (0x[0-9a-fA-F]+), tid: (\d+)",
                line,
            )
            if match:
                return PanickedThread(
                    address=int(match.group(1), 16),
                    backtrace=int(match.group(2), 16),
                    tid=int(match.group(3)),
                )
        return None

    @cached_property
    def kernel_extensions_in_backtrace(self) -> List[KernelExtension]:
        result = []
        in_section = False
        for line in self._panic_lines():
            stripped = line.strip()
            if stripped == "Kernel Extensions in backtrace:":
                in_section = True
                continue
            if not in_section:
                continue
            if not stripped:
                break
            if stripped.startswith("dependency:"):
                continue
            match = re.match(
                r"(.+)\((.+)\)\[([0-9A-F-]+)]@(0x[0-9a-fA-F]+)->(0x[0-9a-fA-F]+)",
                stripped,
            )
            if match:
                result.append(
                    KernelExtension(
                        name=match.group(1),
                        version=match.group(2),
                        uuid=match.group(3),
                        start=int(match.group(4), 16),
                        end=int(match.group(5), 16),
                    )
                )
        return result

    @cached_property
    def last_started_kext(self) -> Optional[str]:
        for line in self._panic_lines():
            if line.startswith("last started kext at "):
                return line.split(": ", 1)[1]
        return None

    @cached_property
    def loaded_kexts(self) -> List[str]:
        result = []
        in_section = False
        for line in self._panic_lines():
            if line == "loaded kexts:":
                in_section = True
                continue
            if not in_section:
                continue
            if not line.strip():
                break
            result.append(line.strip())
        return result

    def _render_details(self, text: Text) -> None:
        if self.panic_string:
            _render_field(text, "Panic", self.panic_string, STYLE_FAILURE)
        if self.exit_reason:
            _render_field(text, "Exit reason", self.exit_reason, STYLE_DETAIL)
        if self.debugger_message:
            _render_field(text, "Debugger message", self.debugger_message, STYLE_DETAIL)
        if self.panicked_task:
            text.append("Panicked task: ", style=STYLE_LABEL)
            text.append(self.panicked_task.name, style=STYLE_IMAGE)
            text.append(
                f" (pid {self.panicked_task.pid}, {self.panicked_task.threads} threads)\n"
            )
        if self.panicked_thread:
            text.append("Panicked thread: ", style=STYLE_LABEL)
            text.append(f"tid {self.panicked_thread.tid} @ ")
            text.append(f"0x{self.panicked_thread.address:x}\n", style=STYLE_ADDRESS)
        if self.kernel_extensions_in_backtrace:
            text.append("Kernel Extensions in backtrace:\n", style=STYLE_LABEL)
            for extension in self.kernel_extensions_in_backtrace:
                text.append("\t")
                text.append(extension.name, style=STYLE_IMAGE)
                text.append(f" {extension.version} ")
                text.append(f"[{extension.uuid}]\n", style=STYLE_IDENTIFIER)
        if self.panicked_thread_frames:
            text.append("Panicked thread backtrace:\n", style=STYLE_LABEL)
            for frame in self.panicked_thread_frames:
                self._render_frame(text, frame)
            self._render_missing_symbols(text)

    def _thread_marker(self, thread: StackshotThread) -> Optional[str]:
        if self.panicked_thread and thread.tid == self.panicked_thread.tid:
            return "panicked"
        return None

    def _render_missing_symbols(self, text: Text) -> None:
        """Say which symbols would name the frames left unnamed."""
        frames = self.panicked_thread_frames
        if any(frame.kernel for frame in frames):
            if self.kernel_symbols is None:
                text.append(
                    "\tKernel frames are named given the kernelcache the device ran.\n",
                    style=STYLE_IDENTIFIER,
                )
            elif not self.kernel_symbols.has_symbols:
                text.append(
                    "\tThe kernelcache holds no symbols, kernel frames are named given signatures for it.\n",
                    style=STYLE_IDENTIFIER,
                )
        if self.device_support_symbols is None and not all(
            frame.kernel for frame in frames
        ):
            text.append(
                f"\tUser frames are named given the Xcode DeviceSupport of "
                f"{self.product_type} ({self.build_version}).\n",
                style=STYLE_IDENTIFIER,
            )


@dataclass
class SpindumpImage:
    """A binary image a process of a spindump report had loaded."""

    name: str
    uuid: str
    start: int
    #: Unknown for some images, the executable of the process among them
    end: Optional[int] = None
    path: Optional[str] = None


@dataclass
class SpindumpFrame:
    """A node of a call tree of a spindump report: a frame, and the frames it called."""

    #: How many samples went through this frame
    count: int
    #: ``None`` for a line which is not a frame, such as ``<Kernel mode>``
    address: Optional[int] = None
    image: Optional[str] = None
    image_offset: Optional[int] = None
    symbol: Optional[str] = None
    symbol_offset: Optional[int] = None
    #: The text of a line which is not a frame
    note: Optional[str] = None
    children: List["SpindumpFrame"] = field(default_factory=list)

    def walk(self, depth: int = 0) -> Iterator[Tuple[int, "SpindumpFrame"]]:
        """Go over this frame and the ones below it, each with its depth."""
        yield depth, self
        for child in self.children:
            yield from child.walk(depth + 1)


@dataclass
class SpindumpProcess:
    """A process of a spindump report, with the call tree its samples make."""

    name: str
    pid: Optional[int] = None
    #: What the report tells of the process, e.g. ``Footprint`` or ``Num samples``
    fields: Mapping[str, str] = field(default_factory=dict)
    #: The outermost frames
    frames: List[SpindumpFrame] = field(default_factory=list)
    images: List[SpindumpImage] = field(default_factory=list)

    @property
    def uuid(self) -> Optional[str]:
        return self.fields.get("UUID")

    @property
    def path(self) -> Optional[str]:
        return self.fields.get("Path")

    def image_at(self, address: int) -> Optional[SpindumpImage]:
        """The image holding ``address``."""
        found = None
        for image in self.images:
            if image.start <= address and (found is None or image.start > found.start):
                found = image
        if found is not None and found.end is not None and address > found.end:
            return None
        return found

    def walk(self) -> Iterator[Tuple[int, SpindumpFrame]]:
        """Go over every frame of the call tree, each with its depth."""
        for frame in self.frames:
            yield from frame.walk()


class SpindumpCrashReport(ProcessesReport):
    """A report of what processes were doing over a while, as spindump writes for a resource limit.

    A process went over its limit of disk writes, CPU or wakeups, and the samples taken of it
    meanwhile make a call tree for each process involved.
    """

    BUG_TYPES = (
        BugType.SymptomsIO,
        BugType.SymptomsCPUUsage,
        BugType.SymptomsCPUUsageFatal,
        BugType.SymptomsCPUWakes,
    )

    _FIELD = re.compile(r"^([^:\s][^:]*):\s*(.*)$")
    _STACK_LINE = re.compile(r"^( +)(\d+)\s+(.+)$")
    _FRAME = re.compile(
        r"^(?:\?\?\?|(?P<symbol>.+?)(?: \+ (?P<symbol_offset>\d+))?) "
        r"\((?P<image>.+) \+ (?P<image_offset>\d+)\) \[(?P<address>0x[0-9a-fA-F]+)\]$"
    )
    _IMAGE = re.compile(
        r"^\s+(0x[0-9a-fA-F]+) -\s+(0x[0-9a-fA-F]+|\?\?\?)\s+(.+?)\s+<([0-9A-Fa-f-]{36})>(?:\s+(.*))?$"
    )
    _PROCESS = re.compile(
        r"^Powerstats for:\s+(.+?)(?: \[(\d+)\])?(?: \[unique pid \d+\])?$"
    )
    _HEAVIEST_STACK = "Heaviest stack for the target process:"

    def _text(self) -> str:
        return self._data if isinstance(self._data, str) else ""

    @cached_property
    def _sections(self) -> List[List[str]]:
        """The lines of the report, split where a process starts. The first describe the event."""
        sections: List[List[str]] = [[]]
        for line in self._text().splitlines():
            if self._PROCESS.match(line):
                sections.append([])
            sections[-1].append(line)
        return sections

    @classmethod
    def _parse_fields(cls, lines: Iterable[str]) -> dict:
        fields: dict = {}
        for line in lines:
            match = cls._FIELD.match(line)
            # the first one wins: a process repeats some of the event's under its own
            if match and match.group(1) not in fields:
                fields[match.group(1)] = match.group(2)
        return fields

    @classmethod
    def _parse_frame(cls, count: int, text: str) -> SpindumpFrame:
        match = cls._FRAME.match(text)
        if match is None:
            return SpindumpFrame(count=count, note=text)
        symbol_offset = match.group("symbol_offset")
        return SpindumpFrame(
            count=count,
            address=int(match.group("address"), 16),
            image=match.group("image"),
            image_offset=int(match.group("image_offset")),
            symbol=match.group("symbol"),
            symbol_offset=(
                int(symbol_offset or 0) if match.group("symbol") is not None else None
            ),
        )

    @classmethod
    def _parse_tree(cls, lines: Iterable[str]) -> List[SpindumpFrame]:
        """Read a call tree, where a frame is indented below the one which called it."""
        roots: List[SpindumpFrame] = []
        path: List[Tuple[int, SpindumpFrame]] = []
        for line in lines:
            match = cls._STACK_LINE.match(line)
            if match is None:
                continue
            indent = len(match.group(1))
            frame = cls._parse_frame(int(match.group(2)), match.group(3))
            while path and path[-1][0] >= indent:
                path.pop()
            (path[-1][1].children if path else roots).append(frame)
            path.append((indent, frame))
        return roots

    @cached_property
    def fields(self) -> Mapping[str, str]:
        """What the report tells of the event, e.g. ``Event``, ``Command`` or ``Duration``."""
        lines = self._sections[0]
        if self._HEAVIEST_STACK in lines:
            lines = lines[: lines.index(self._HEAVIEST_STACK)]
        return self._parse_fields(lines)

    @property
    def event(self) -> Optional[str]:
        """What the report is about, e.g. ``disk writes`` or ``cpu usage``."""
        return self.fields.get("Event")

    @property
    def command(self) -> Optional[str]:
        """Name of the process the report is about."""
        return self.fields.get("Command")

    @property
    def pid(self) -> Optional[int]:
        pid = self.fields.get("PID", "")
        return int(pid) if pid.isdigit() else None

    @property
    def product_type(self) -> Optional[str]:
        return self.fields.get("Hardware model")

    @property
    def build_version(self) -> Optional[str]:
        # "iPhone OS 27.2.1 (Build 24B91034)"
        match = re.search(
            r"\((?:Build )?([^)]+)\)\s*$", self.fields.get("OS Version", "")
        )
        return match.group(1) if match else None

    def _name_frames(
        self, process: SpindumpProcess, frames: Iterable[SpindumpFrame]
    ) -> None:
        """Name the frames the report left unnamed, using the symbols of the images of the process."""
        symbols = self.device_support_symbols
        if symbols is None:
            return
        for frame in frames:
            if frame.address is None or frame.symbol is not None:
                continue
            image = process.image_at(frame.address)
            if image is None:
                continue
            symbol_image = symbols.image_by_uuid(image.uuid)
            if symbol_image is None:
                continue
            # only where a sample ended is the address not one to return to
            innermost = not any(child.address is not None for child in frame.children)
            symbol = self._symbolicate_user_frame(
                symbol_image, frame.address - image.start, innermost
            )
            if symbol is not None:
                frame.symbol, frame.symbol_offset = symbol

    @cached_property
    def processes(self) -> List[SpindumpProcess]:
        """Every process the report holds, with the call tree of its samples."""
        result = []
        for lines in self._sections[1:]:
            match = self._PROCESS.match(lines[0])
            stack_start = next(
                (i for i, line in enumerate(lines) if self._STACK_LINE.match(line)),
                len(lines),
            )
            images_start = next(
                (i for i, line in enumerate(lines) if line.strip() == "Binary Images:"),
                len(lines),
            )
            process = SpindumpProcess(
                name=match.group(1),
                pid=int(match.group(2)) if match.group(2) else None,
                fields=self._parse_fields(lines[1:stack_start]),
                frames=self._parse_tree(lines[stack_start:images_start]),
            )
            for line in lines[images_start:]:
                image = self._IMAGE.match(line)
                if image:
                    process.images.append(
                        SpindumpImage(
                            # an identifier and a version may come where the name does
                            name=posixpath.basename(image.group(5) or "")
                            or image.group(3),
                            uuid=image.group(4).lower(),
                            start=int(image.group(1), 16),
                            end=None
                            if image.group(2) == "???"
                            else int(image.group(2), 16),
                            path=image.group(5) or None,
                        )
                    )
            self._name_frames(process, (frame for _depth, frame in process.walk()))
            result.append(process)
        return result

    @cached_property
    def target_process(self) -> Optional[SpindumpProcess]:
        """The process the report is about."""
        return next(
            (process for process in self.processes if process.pid == self.pid),
            self.processes[0] if self.processes else None,
        )

    @cached_property
    def heaviest_stack(self) -> List[SpindumpFrame]:
        """The call stack most samples of the target process went through, outermost first."""
        lines = self._sections[0]
        if self._HEAVIEST_STACK not in lines:
            return []
        frames = []
        for line in lines[lines.index(self._HEAVIEST_STACK) + 1 :]:
            match = self._STACK_LINE.match(line)
            if match is None:
                break
            frames.append(self._parse_frame(int(match.group(2)), match.group(3)))
        # each one called the next, which is what tells a frame from where a sample ended
        for caller, callee in zip(frames, frames[1:]):
            caller.children = [callee]
        if self.target_process is not None:
            self._name_frames(self.target_process, frames)
        for frame in frames:
            frame.children = []
        return frames

    def _render_details(self, text: Text) -> None:
        if self.event:
            _render_field(text, "Event", self.event, STYLE_FAILURE)
        if self.command:
            text.append("Process: ", style=STYLE_LABEL)
            text.append(self.command, style=STYLE_IMAGE)
            text.append(f" (pid {self.pid})\n" if self.pid is not None else "\n")
        # what went over which limit: the lines the report gives next to its event
        names = list(self.fields)
        if "Event" in names:
            for name in names[names.index("Event") + 1 :]:
                if name == "Hardware model":
                    break
                text.append(f"{name}: ", style=STYLE_LABEL)
                text.append(f"{self.fields[name]}\n", style=STYLE_DETAIL)
        if self.product_type:
            text.append("Device: ", style=STYLE_LABEL)
            text.append(f"{self.product_type}, {self.fields.get('OS Version')}\n")
        if self.heaviest_stack:
            text.append("Heaviest stack:\n", style=STYLE_LABEL)
            for frame in self.heaviest_stack:
                self._render_frame(text, frame, indent="\t")
            if self.device_support_symbols is None and any(
                frame.symbol is None for frame in self.heaviest_stack
            ):
                text.append(
                    f"\tFrames are named given the Xcode DeviceSupport of "
                    f"{self.product_type} ({self.build_version}).\n",
                    style=STYLE_IDENTIFIER,
                )

    def render_processes(self, processes: Iterable[SpindumpProcess]) -> Text:
        """Render the call tree of the given processes, each frame after its count of samples."""
        text = Text()
        for process in processes:
            text.append("Process: ", style=STYLE_LABEL)
            text.append(process.name or "?", style=STYLE_IMAGE)
            details = [] if process.pid is None else [f"pid {process.pid}"]
            if process.fields.get("Num samples"):
                details.append(f"samples: {process.fields['Num samples']}")
            text.append(f" ({', '.join(details)})\n" if details else "\n")
            for depth, frame in process.walk():
                self._render_frame(text, frame, indent="\t" + "  " * depth)
        return text

    @staticmethod
    def _render_frame(text: Text, frame: SpindumpFrame, indent: str) -> None:
        text.append(f"{indent}{frame.count:<3} ")
        if frame.address is None:
            text.append(f"{frame.note}\n", style=STYLE_IDENTIFIER)
            return
        _render_location(
            text,
            frame.image,
            frame.address,
            frame.symbol,
            frame.symbol_offset,
            frame.image_offset,
        )


def render_processes(
    report: CrashReportBase,
    processes: Iterable[str] = (),
    all_processes: bool = False,
    running: bool = False,
) -> Optional[Text]:
    """Render the processes asked of a report: what ``--process``, ``--all`` and ``--running`` print.

    :param processes: Name or pid of the processes to render.
    :param all_processes: Render every process of the report, or every thread of a userland crash.
    :param running: Render the threads which were on a CPU, of a panic or a stackshot.
    :returns: ``None`` when no process was asked for.
    :raises ValueError: for processes asked of a report which holds none, or not the ones asked for.
    """
    requested = list(processes)
    if not (requested or all_processes or running):
        return None
    if isinstance(report, UserModeCrashReport):
        # a single process: all there is to list are its threads
        if requested or running:
            raise ValueError(
                "--process and --running apply to panic, stackshot and spindump reports only"
            )
        return report.render_threads()
    if not isinstance(report, ProcessesReport):
        raise ValueError(
            "--process, --all and --running apply to crash, panic, stackshot and spindump reports only"
        )
    if running and not isinstance(report, StackshotReportBase):
        raise ValueError("--running applies to panic and stackshot reports only")
    selected: list = []
    if all_processes:
        selected = list(report.processes)
    elif running:
        selected = list(report.running_processes)
    for name in requested:
        found = report.find_processes(name)
        if not found:
            raise ValueError(f"The report holds no process {name}")
        selected += [entry for entry in found if entry not in selected]
    return report.render_processes(selected)


def get_crash_report_from_file(crash_report_file: IO) -> CrashReportBase:
    """Parse a report, its metadata line first, with the class dedicated to its bug type."""
    header = json.loads(crash_report_file.readline())
    report_class = CrashReportBase.parser_for(header["bug_type"])
    return report_class(header, crash_report_file.read(), crash_report_file.name)


def get_crash_report_from_buf(
    crash_report_buf: str, filename: Optional[str] = None
) -> CrashReportBase:
    file = StringIO(crash_report_buf)
    file.name = filename
    return get_crash_report_from_file(file)


def parse_report(path: Union[str, "os.PathLike[str]"]) -> CrashReportBase:
    """Parse the report stored at ``path``, which becomes its ``filename``."""
    # reports are UTF-8 whatever the platform's default encoding is
    with open(path, encoding="utf-8") as report:
        return get_crash_report_from_file(report)
