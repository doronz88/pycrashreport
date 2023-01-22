import click
from la_panic.panic_parser.kernel_panic import KernelPanic

from pycrashreport.crash_report import CrashReport


@click.command()
@click.argument('file', type=click.File('rt'))
@click.option('-p', '--panic', is_flag=True, default=False, help="set for kernel panic")
def cli(file, panic):
    if panic:
        print(KernelPanic(file.read(), filename=file.name))
    else:
        print(CrashReport(file.read(), filename=file.name))


if __name__ == '__main__':
    cli()
