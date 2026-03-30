from typing import Annotated

import typer

from pycrashreport.crash_report import get_crash_report_from_file


def main(file: Annotated[typer.FileText, typer.Argument()]) -> None:
    print(get_crash_report_from_file(file))


def cli() -> None:
    typer.run(main)


if __name__ == "__main__":
    cli()
