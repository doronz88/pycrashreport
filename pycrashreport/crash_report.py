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
from typing import IO, Any, ClassVar, Iterable, List, Mapping, Optional, Union

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
KERNEL_IMAGE_NAME = "kernel"


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
class PanicFrame:
    """One address of a call stack of a panic report, innermost first."""

    address: int
    kernel: bool = False
    #: File name of the containing image when the symbols tell it, its UUID otherwise
    image: Optional[str] = None
    image_offset: Optional[int] = None
    symbol: Optional[str] = None
    symbol_offset: Optional[int] = None


@dataclass
class PanicThread:
    tid: int
    name: Optional[str] = None
    #: The kernel stack of a thread caught in the kernel comes on top of its user stack
    frames: List[PanicFrame] = field(default_factory=list)


@dataclass
class PanicProcess:
    pid: int
    name: str
    threads: List[PanicThread] = field(default_factory=list)


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
    def incident_id(self):
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


class UserModeCrashReport(CrashReportBase):
    BUG_TYPES = (
        BugType.Crash_109,
        BugType.Crash_309,
        BugType.ExcResourceThreads_327,
        BugType.ExcResource_385,
    )

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

    @cached_property
    def frames(self) -> List[Frame]:
        result = []
        if self._is_json:
            thread_index = self.faulting_thread
            images = self._data["usedImages"]
            for frame in self._data["threads"][thread_index]["frames"]:
                image = images[frame["imageIndex"]]
                symbol = frame.get("symbol")
                symbol_offset = frame.get("symbolLocation")
                if symbol is None:
                    # the device names what it can; the rest is up to the host's symbols
                    named = self._symbolicate_json_frame(
                        image, frame, innermost=not result
                    )
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
        else:
            in_frames = False
            for line in self._data.split("\n"):
                if in_frames:
                    splitted = line.split()

                    if len(splitted) == 0:
                        break

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

                if line.startswith(f"Thread {self.faulting_thread} Crashed:"):
                    in_frames = True

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
            in_frames = False
            for line in self._data.split("\n"):
                if in_frames:
                    splitted = line.split()

                    if len(splitted) == 0:
                        break

                    for i in range(0, len(splitted), 2):
                        register_name = splitted[i]
                        if not register_name.endswith(":"):
                            break

                        register_name = register_name[:-1]
                        register_value = int(splitted[i + 1], 16)

                        result.append(
                            Register(name=register_name, value=register_value)
                        )

                if line.startswith(
                    f"Thread {self.faulting_thread} crashed with ARM Thread State"
                ):
                    in_frames = True

        return result

    @cached_property
    def exception_type(self):
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
        result = ""
        if self._is_json:
            asi = self._data.get("asi")
            if asi is None:
                return None
            return asi
        else:
            in_frames = False
            for line in self._data.split("\n"):
                if in_frames:
                    line = line.strip()
                    if len(line) == 0:
                        break

                    result += line + "\n"

                if line.startswith("Application Specific Information:"):
                    in_frames = True

        result = result.strip()
        if not result:
            return None
        return result

    def _render_details(self, text: Text) -> None:
        text.append("Exception: ", style=STYLE_LABEL)
        text.append(f"{self.exception_type}\n", style=STYLE_FAILURE)

        if self.exception_subtype:
            text.append("Exception Subtype: ", style=STYLE_LABEL)
            text.append(f"{self.exception_subtype}\n", style=STYLE_DETAIL)

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


class KernelModeCrashReport(CrashReportBase):
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

    #: Symbols naming the kernel frames, which need the kernelcache the device ran. Assign them
    #: before reading any frames.
    kernel_symbols: Optional[KernelSymbols] = None

    def _report_field(self, name: str) -> Optional[str]:
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

    @cached_property
    def _reported_kernel_images(self) -> dict:
        """Names the panic text itself gives to kernel images, by their lowercase UUID."""
        names = {}
        if self.kernel_uuid:
            names[self.kernel_uuid.lower()] = KERNEL_IMAGE_NAME
        for extension in self.kernel_extensions_in_backtrace:
            names[extension.uuid.lower()] = extension.name
        return names

    def _kernel_frame(
        self, uuid: str, base: int, offset: int, innermost: bool
    ) -> PanicFrame:
        frame = PanicFrame(
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
        delta = 0 if innermost else 1
        # the report gives where `__TEXT_EXEC` of a kernel image got loaded
        symbol = self.kernel_symbols.symbolicate(image.text_exec + offset - delta)
        if symbol is not None:
            frame.symbol = symbol[0]
            frame.symbol_offset = symbol[1] + delta
        return frame

    def _user_frame(
        self, uuid: str, base: int, kind: str, offset: int, innermost: bool
    ) -> PanicFrame:
        frame = PanicFrame(address=base + offset, image=uuid, image_offset=offset)
        symbols = self.device_support_symbols
        if symbols is None:
            return frame
        if kind == IMAGE_KIND_SHARED_CACHE:
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

    def _frames(self, thread: Mapping[str, Any]) -> List[PanicFrame]:
        images = self._report_field("binaryImages") or []
        frames: List[PanicFrame] = []
        for key in ("kernelFrames", "userFrames"):
            for index, offset in thread.get(key) or []:
                if not 0 <= index < len(images):
                    continue
                uuid, base, kind = images[index][:3]
                if kind == IMAGE_KIND_ABSOLUTE:
                    if offset:
                        frames.append(
                            PanicFrame(address=offset, kernel=key == "kernelFrames")
                        )
                elif kind in IMAGE_KINDS_KERNEL:
                    frames.append(self._kernel_frame(uuid, base, offset, not frames))
                else:
                    frames.append(
                        self._user_frame(uuid, base, kind, offset, not frames)
                    )
        return frames

    @cached_property
    def processes(self) -> List[PanicProcess]:
        """Every process the report holds, with the call stack of each of its threads."""
        result = []
        for pid, process in (self._report_field("processByPid") or {}).items():
            panic_process = PanicProcess(
                pid=int(pid), name=process.get("procname") or ""
            )
            for tid, thread in (process.get("threadById") or {}).items():
                panic_process.threads.append(
                    PanicThread(
                        tid=int(tid),
                        name=thread.get("name"),
                        frames=self._frames(thread),
                    )
                )
            result.append(panic_process)
        return result

    @cached_property
    def panicked_thread_frames(self) -> List[PanicFrame]:
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
            text.append("Panic: ", style=STYLE_LABEL)
            text.append(f"{self.panic_string}\n", style=STYLE_FAILURE)
        if self.exit_reason:
            text.append("Exit reason: ", style=STYLE_LABEL)
            text.append(f"{self.exit_reason}\n", style=STYLE_DETAIL)
        if self.debugger_message:
            text.append("Debugger message: ", style=STYLE_LABEL)
            text.append(f"{self.debugger_message}\n", style=STYLE_DETAIL)
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

    def find_processes(self, process: str) -> List[PanicProcess]:
        """Get the processes of the report with the given name, or the one with the given pid."""
        if process.isdigit():
            return [found for found in self.processes if found.pid == int(process)]
        return [found for found in self.processes if found.name == process]

    def render_processes(self, processes: Iterable[PanicProcess]) -> Text:
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
                if self.panicked_thread and thread.tid == self.panicked_thread.tid:
                    text.append(" (panicked)", style=STYLE_FAILURE)
                text.append("\n")
                for frame in thread.frames:
                    self._render_frame(text, frame, indent="\t\t")
        return text

    @staticmethod
    def _render_frame(text: Text, frame: PanicFrame, indent: str = "\t") -> None:
        text.append(indent)
        text.append("kernel" if frame.kernel else "user  ", style=STYLE_IDENTIFIER)
        text.append(" [")
        text.append(frame.image or "?", style=STYLE_IMAGE)
        text.append("] ")
        text.append(f"0x{frame.address:x}", style=STYLE_ADDRESS)
        if frame.symbol is not None:
            text.append(" (")
            text.append(frame.symbol, style=STYLE_SYMBOL)
            text.append(f" + 0x{frame.symbol_offset:x})")
        elif frame.image_offset is not None:
            text.append(" (+ ")
            text.append(f"0x{frame.image_offset:x}", style=STYLE_ADDRESS)
            text.append(")")
        text.append("\n")

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


def get_crash_report_from_file(crash_report_file: IO) -> CrashReportBase:
    """Parse a report, its metadata line first, with the class dedicated to its bug type."""
    header = json.loads(crash_report_file.readline())
    report_class = CrashReportBase.parser_for(header["bug_type"])
    return report_class(header, crash_report_file.read(), crash_report_file.name)


def get_crash_report_from_buf(
    crash_report_buf: str, filename: str = None
) -> CrashReportBase:
    file = StringIO(crash_report_buf)
    file.name = filename
    return get_crash_report_from_file(file)


def parse_report(path: Union[str, "os.PathLike[str]"]) -> CrashReportBase:
    """Parse the report stored at ``path``, which becomes its ``filename``."""
    # reports are UTF-8 whatever the platform's default encoding is
    with open(path, encoding="utf-8") as report:
        return get_crash_report_from_file(report)
