import click
import json
from pathlib import Path

from la_panic.panic_parser.kernel_panic import KernelPanic
from pycrashreport.crash_report import CrashReport


def parse_crash(crash_report_file: click.File) -> object:
    __KERNEL_PANIC_BUG_TYPES = [10, 110, 210]

    with Path(crash_report_file.name).open("rb") as crash_report_filename:
        raw_metadata = crash_report_filename.readline()
        metadata = json.loads(raw_metadata)

        bug_type = int(metadata["bug_type"])
        if bug_type in __KERNEL_PANIC_BUG_TYPES:
            return KernelPanic(crash_report_file.read(), crash_report_file.name)

        return CrashReport(crash_report_file.read(), crash_report_file.name)


@click.command()
@click.argument('file', type=click.File('rt'))
def cli(file):
    print(parse_crash(file))


if __name__ == '__main__':
    cli()
