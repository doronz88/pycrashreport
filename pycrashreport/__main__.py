from typing import Annotated

import typer
from rich.console import Console

from pycrashreport.crash_report import get_crash_report_from_file


def main(file: Annotated[typer.FileText, typer.Argument()]) -> None:
    # printed as a renderable, so colors follow the terminal: none when the output is piped
    Console(highlight=False).print(get_crash_report_from_file(file), soft_wrap=True)


def cli() -> None:
    typer.run(main)


if __name__ == "__main__":
    cli()
