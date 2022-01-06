import click

from pycrashreport.crash_report import CrashReport


@click.command()
@click.argument('file', type=click.File('rt'))
def cli(file):
    print(CrashReport(file.read(), filename=file.name))


if __name__ == '__main__':
    cli()
