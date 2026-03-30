import json
import posixpath
import re
from collections import namedtuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from functools import cached_property
from io import StringIO
from typing import IO, List, Mapping, Optional

import typer

Frame = namedtuple("Frame", "image_name image_base image_offset symbol symbol_offset")
Register = namedtuple("Register", "name value")
KernelExtension = namedtuple("KernelExtension", "name version uuid start end")


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
    def __init__(self, metadata: Mapping, data: str, filename: str = None):
        self.filename = filename
        self._metadata = metadata
        self._data = data
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

    def __repr__(self) -> str:
        filename = ""
        if self.filename:
            filename = f"FILENAME:{posixpath.basename(self.filename)} "
        return f"<{self.__class__} {filename}TIMESTAMP:{self.timestamp}>"

    def __str__(self) -> str:
        filename = ""
        if self.filename:
            filename = self.filename

        return typer.style(
            f"{self.incident_id} {self.timestamp}\n{filename}\n\n", fg=typer.colors.CYAN
        )


class UserModeCrashReport(CrashReportBase):
    def _parse_field(self, name: str) -> str:
        name += ":"
        for line in self._data.split("\n"):
            if line.startswith(name):
                field = line.split(name, 1)[1]
                field = field.strip()
                return field

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
                result.append(
                    Frame(
                        image_name=image.get("path"),
                        image_base=image.get("base"),
                        symbol=frame.get("symbol"),
                        image_offset=frame.get("imageOffset"),
                        symbol_offset=frame.get("symbolLocation"),
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

    def __str__(self) -> str:
        result = super().__str__()
        result += typer.style(f"Exception: {self.exception_type}\n", bold=True)

        if self.exception_subtype:
            result += typer.style("Exception Subtype: ", bold=True)
            result += f"{self.exception_subtype}\n"

        if self.application_specific_information:
            result += typer.style("Application Specific Information: ", bold=True)
            result += str(self.application_specific_information)

        result += "\n"

        result += typer.style("Registers:", bold=True)
        for i, register in enumerate(self.registers):
            if i % 4 == 0:
                result += "\n"

            result += f"{register.name} = 0x{register.value:016x} ".rjust(30)

        result += "\n\n"

        result += typer.style("Frames:\n", bold=True)
        for frame in self.frames:
            image_base = "_HEADER"
            if frame.image_base is not None:
                image_base = f"0x{frame.image_base:x}"
            result += f"\t[{frame.image_name}] {image_base}"
            if frame.image_offset:
                result += f" + 0x{frame.image_offset:x}"
            if frame.symbol is not None:
                result += f" ({frame.symbol} + 0x{frame.symbol_offset:x})"
            result += "\n"

        return result


class KernelModeCrashReport(CrashReportBase):
    def _parse(self):
        super()._parse()
        self._panic_text = ""
        if self._is_json and isinstance(self._data, dict):
            self._panic_text = (
                self._data.get("string") or self._data.get("panicString") or ""
            )
        elif isinstance(self._data, str):
            self._panic_text = self._data

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

    def __str__(self) -> str:
        result = super().__str__()
        if self.panic_string:
            result += typer.style(f"Panic: {self.panic_string}\n", bold=True)
        if self.debugger_message:
            result += typer.style("Debugger message: ", bold=True)
            result += f"{self.debugger_message}\n"
        if self.panicked_task:
            result += typer.style("Panicked task: ", bold=True)
            result += (
                f"{self.panicked_task.name} (pid {self.panicked_task.pid}, "
                f"{self.panicked_task.threads} threads)\n"
            )
        if self.panicked_thread:
            result += typer.style("Panicked thread: ", bold=True)
            result += (
                f"tid {self.panicked_thread.tid} @ 0x{self.panicked_thread.address:x}\n"
            )
        if self.kernel_extensions_in_backtrace:
            result += typer.style("Kernel Extensions in backtrace:\n", bold=True)
            for extension in self.kernel_extensions_in_backtrace:
                result += f"\t{extension.name} {extension.version} [{extension.uuid}]\n"
        return result

    @cached_property
    def bug_type(self) -> BugType:
        return BugType(self._metadata["bug_type"])


def get_crash_report_from_file(crash_report_file: IO) -> CrashReportBase:
    metadata = json.loads(crash_report_file.readline())

    try:
        bug_type = BugType(metadata["bug_type"])
    except ValueError:
        return CrashReportBase(
            metadata, crash_report_file.read(), crash_report_file.name
        )

    bug_type_parsers = {
        BugType.ForceReset: KernelModeCrashReport,
        BugType.Panic_210: KernelModeCrashReport,
        BugType.Crash_109: UserModeCrashReport,
        BugType.Crash_309: UserModeCrashReport,
        BugType.ExcResourceThreads_327: UserModeCrashReport,
        BugType.ExcResource_385: UserModeCrashReport,
    }

    parser = bug_type_parsers.get(bug_type)
    if parser is None:
        return CrashReportBase(
            metadata, crash_report_file.read(), crash_report_file.name
        )

    return parser(metadata, crash_report_file.read(), crash_report_file.name)


def get_crash_report_from_buf(
    crash_report_buf: str, filename: str = None
) -> CrashReportBase:
    file = StringIO(crash_report_buf)
    file.name = filename
    return get_crash_report_from_file(file)
