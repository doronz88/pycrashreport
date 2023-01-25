import json
import posixpath
from collections import namedtuple
from datetime import datetime
from enum import Enum
from io import StringIO
from typing import List, Optional, Mapping, IO

import click
from cached_property import cached_property
from la_panic.panic_parser.bug_type import BugType as KernelPanicBugType
from la_panic.panic_parser.kernel_panic import KernelPanic

Frame = namedtuple('Frame', 'image_name image_base image_offset symbol symbol_offset')
Register = namedtuple('Register', 'name value')


class BugType(Enum):
    Crash_109 = '109'
    Crash_309 = '309'
    ExcResourceThreads = '327'
    ExcResource = '385'
    ForceReset = KernelPanicBugType.FORCE_RESET.value
    Panic = KernelPanicBugType.FULL.value


class CrashReportBase:
    def __init__(self, metadata: Mapping, data: str, filename: str = None):
        self.filename = filename
        self._metadata = metadata
        self._data = data
        self._parse()

    def _parse(self):
        self._is_json = False
        try:
            self._data = json.loads(self._data)
            self._is_json = True
        except json.decoder.JSONDecodeError:
            pass

    @cached_property
    def bug_type(self) -> BugType:
        return BugType(self._metadata['bug_type'])

    @cached_property
    def incident_id(self):
        return self._metadata.get('incident_id')

    @cached_property
    def timestamp(self) -> datetime:
        timestamp = self._metadata.get('timestamp')
        timestamp_without_timezone = timestamp.rsplit(' ', 1)[0]
        return datetime.strptime(timestamp_without_timezone, '%Y-%m-%d %H:%M:%S.%f')

    @cached_property
    def name(self) -> str:
        return self._metadata.get('name')

    def __repr__(self) -> str:
        filename = ''
        if self.filename:
            filename = f'FILENAME:{posixpath.basename(self.filename)} '
        return f'<{self.__class__} {filename}TIMESTAMP:{self.timestamp}>'

    def __str__(self) -> str:
        filename = ''
        if self.filename:
            filename = self.filename

        return click.style(f'{self.incident_id} {self.timestamp}\n{filename}\n\n', fg='cyan')


class UserModeCrashReport(CrashReportBase):
    def _parse_field(self, name: str) -> str:
        name += ':'
        for line in self._data.split('\n'):
            if line.startswith(name):
                field = line.split(name, 1)[1]
                field = field.strip()
                return field

    @cached_property
    def faulting_thread(self) -> int:
        if self._is_json:
            return self._data['faultingThread']
        else:
            return int(self._parse_field('Triggered by Thread'))

    @cached_property
    def frames(self) -> List[Frame]:
        result = []
        if self._is_json:
            thread_index = self.faulting_thread
            images = self._data['usedImages']
            for frame in self._data['threads'][thread_index]['frames']:
                image = images[frame['imageIndex']]
                result.append(
                    Frame(image_name=image.get('path'), image_base=image.get('base'), symbol=frame.get('symbol'),
                          image_offset=frame.get('imageOffset'), symbol_offset=frame.get('symbolLocation')))
        else:
            in_frames = False
            for line in self._data.split('\n'):
                if in_frames:
                    splitted = line.split()

                    if len(splitted) == 0:
                        break

                    assert splitted[-2] == '+'
                    image_base = splitted[-3]
                    if image_base.startswith('0x'):
                        result.append(Frame(image_name=splitted[1], image_base=int(image_base, 16), symbol=None,
                                            image_offset=int(splitted[-1]), symbol_offset=None))
                    else:
                        # symbolicated
                        result.append(Frame(image_name=splitted[1], image_base=None, symbol=image_base,
                                            image_offset=None, symbol_offset=int(splitted[-1])))

                if line.startswith(f'Thread {self.faulting_thread} Crashed:'):
                    in_frames = True

        return result

    @cached_property
    def registers(self) -> List[Register]:
        result = []
        if self._is_json:
            thread_index = self._data['faultingThread']
            thread_state = self._data['threads'][thread_index]['threadState']

            if 'x' in thread_state:
                for i, reg_x in enumerate(thread_state['x']):
                    result.append(Register(name=f'x{i}', value=reg_x['value']))

            for i, (name, value) in enumerate(thread_state.items()):
                if name == 'x':
                    for j, reg_x in enumerate(value):
                        result.append(Register(name=f'x{j}', value=reg_x['value']))
                else:
                    if isinstance(value, dict):
                        result.append(Register(name=name, value=value['value']))
        else:
            in_frames = False
            for line in self._data.split('\n'):
                if in_frames:
                    splitted = line.split()

                    if len(splitted) == 0:
                        break

                    for i in range(0, len(splitted), 2):
                        register_name = splitted[i]
                        if not register_name.endswith(':'):
                            break

                        register_name = register_name[:-1]
                        register_value = int(splitted[i + 1], 16)

                        result.append(Register(name=register_name, value=register_value))

                if line.startswith(f'Thread {self.faulting_thread} crashed with ARM Thread State'):
                    in_frames = True

        return result

    @cached_property
    def exception_type(self):
        if self._is_json:
            return self._data['exception'].get('type')
        else:
            return self._parse_field('Exception Type')

    @cached_property
    def exception_subtype(self) -> Optional[str]:
        if self._is_json:
            return self._data['exception'].get('subtype')
        else:
            return self._parse_field('Exception Subtype')

    @cached_property
    def application_specific_information(self) -> Optional[str]:
        result = ''
        if self._is_json:
            asi = self._data.get('asi')
            if asi is None:
                return None
            return asi
        else:
            in_frames = False
            for line in self._data.split('\n'):
                if in_frames:
                    line = line.strip()
                    if len(line) == 0:
                        break

                    result += line + '\n'

                if line.startswith('Application Specific Information:'):
                    in_frames = True

        result = result.strip()
        if not result:
            return None
        return result

    def __str__(self) -> str:
        result = super().__str__()
        result += click.style(f'Exception: {self.exception_type}\n', bold=True)

        if self.exception_subtype:
            result += click.style('Exception Subtype: ', bold=True)
            result += f'{self.exception_subtype}\n'

        if self.application_specific_information:
            result += click.style('Application Specific Information: ', bold=True)
            result += str(self.application_specific_information)

        result += '\n'

        result += click.style('Registers:', bold=True)
        for i, register in enumerate(self.registers):
            if i % 4 == 0:
                result += '\n'

            result += f'{register.name} = 0x{register.value:016x} '.rjust(30)

        result += '\n\n'

        result += click.style('Frames:\n', bold=True)
        for frame in self.frames:
            image_base = '_HEADER'
            if frame.image_base is not None:
                image_base = f'0x{frame.image_base:x}'
            result += f'\t[{frame.image_name}] {image_base}'
            if frame.image_offset:
                result += f' + 0x{frame.image_offset:x}'
            if frame.symbol is not None:
                result += f' ({frame.symbol} + 0x{frame.symbol_offset:x})'
            result += '\n'

        return result


class KernelModeCrashReport(KernelPanic, CrashReportBase):
    def __init__(self, metadata: Mapping, data: str, filename: str = None):
        CrashReportBase.__init__(self, metadata, data, filename=filename)
        KernelPanic.__init__(self, metadata, data, filename=filename)

    @cached_property
    def bug_type(self) -> BugType:
        return BugType(self._metadata['bug_type'])


def get_crash_report_from_file(crash_report_file: IO) -> CrashReportBase:
    metadata = json.loads(crash_report_file.readline())

    try:
        bug_type = BugType(metadata['bug_type'])
    except ValueError:
        return CrashReportBase(metadata, crash_report_file.read(), crash_report_file.name)

    bug_type_parsers = {
        BugType.ForceReset: KernelModeCrashReport,
        BugType.Panic: KernelModeCrashReport,
        BugType.Crash_109: UserModeCrashReport,
        BugType.Crash_309: UserModeCrashReport,
        BugType.ExcResourceThreads: UserModeCrashReport,
        BugType.ExcResource: UserModeCrashReport,
    }

    parser = bug_type_parsers.get(bug_type)
    if parser is None:
        return CrashReportBase(metadata, crash_report_file.read(), crash_report_file.name)

    return parser(metadata, crash_report_file.read(), crash_report_file.name)


def get_crash_report_from_buf(crash_report_buf: str, filename: str = None) -> CrashReportBase:
    file = StringIO(crash_report_buf)
    file.name = filename
    return get_crash_report_from_file(file)
