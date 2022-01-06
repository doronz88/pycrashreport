import json
from collections import namedtuple
from typing import List, Optional

import click
from cached_property import cached_property

Frame = namedtuple('Frame', 'image_name image_base symbol offset')
Register = namedtuple('Register', 'name value')


class CrashReport:
    def __init__(self, buf: str, filename: str = None):
        self.filename = filename
        self._metadata, self._data = buf.split('\n', 1)
        self._metadata = json.loads(self._metadata)
        self._parse()

    def _parse(self):
        self._is_json = False
        try:
            self._data = json.loads(self._data)
            self._is_json = True
        except json.decoder.JSONDecodeError:
            pass

    def _parse_field(self, name: str) -> str:
        name += ':'
        for line in self._data.split('\n'):
            if line.startswith(name):
                field = line.split(name, 1)[1]
                field = field.strip()
                return field

    @cached_property
    def bug_type(self):
        return self._metadata['bug_type']

    @cached_property
    def incident_id(self):
        return self._metadata['incident_id']

    @cached_property
    def timestamp(self):
        return self._metadata['timestamp']

    @cached_property
    def name(self) -> str:
        return self._metadata['name']

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
                    Frame(image_name=image['path'], image_base=hex(image['base']), symbol=image['symbol'],
                          offset=frame['imageOffset']))
        else:
            in_frames = False
            for line in self._data.split('\n'):
                if in_frames:
                    splitted = line.split()

                    if len(splitted) == 0:
                        break

                    assert splitted[-2] == '+'
                    result.append(Frame(image_name=splitted[1], image_base=int(splitted[-3], 16), symbol=splitted[-4],
                                        offset=int(splitted[-1])))

                if line.startswith(f'Thread {self.faulting_thread} Crashed:'):
                    in_frames = True

        return result

    @cached_property
    def registers(self) -> List[Register]:
        result = []
        if self._is_json:
            thread_index = self._data['faultingThread']
            thread_state = self._data['threads'][thread_index]['threadState']

            for i, reg in enumerate(thread_state['x']):
                result.append(Register(name=f'x{i}', value=reg['value']))

            additional_regs = ('lr', 'cpsr', 'fp', 'sp', 'esr', 'pc', 'far')

            for reg in additional_regs:
                result.append(Register(name=reg, value=thread_state[reg]['value']))
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
    def application_specific_information(self) -> str:
        result = ''
        if self._is_json:
            return str(self._data.get('asi'))
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

        return result.strip()

    def __str__(self):
        filename = ''
        if self.filename:
            filename = self.filename

        result = ''
        result += click.style(f'{self.incident_id} {self.timestamp}\n{filename}\n\n', fg='cyan')

        if self.bug_type not in ('109', '309', '327', '385'):
            # these crashes aren't crash dumps
            return result

        result += click.style(f'Exception: {self.exception_type}\n', bold=True)

        if self.exception_subtype:
            result += click.style('Exception Subtype: ', bold=True)
            result += f'{self.exception_subtype}\n'

        if self.application_specific_information:
            result += click.style('Application Specific Information: ', bold=True)
            result += self.application_specific_information

        result += '\n'

        result += click.style('Registers:', bold=True)
        for i, register in enumerate(self.registers):
            if i % 4 == 0:
                result += '\n'

            result += f'{register.name} = 0x{register.value:016x} '.rjust(30)

        result += '\n\n'

        result += click.style('Frames:\n', bold=True)
        for frame in self.frames:
            result += f'\t[{frame.image_name}] 0x{frame.image_base:x} + 0x{frame.offset:x}\n'

        return result
