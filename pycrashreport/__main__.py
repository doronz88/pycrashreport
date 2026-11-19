from pathlib import Path
from typing import Annotated, Optional

import typer
from apple_symbols import KernelSymbols
from rich.console import Console

from pycrashreport.crash_report import KernelModeCrashReport, get_crash_report_from_file

app = typer.Typer(add_completion=False)


@app.command()
def main(
    file: Annotated[typer.FileText, typer.Argument()],
    kernelcache: Annotated[
        Optional[Path],
        typer.Option(
            help="Kernelcache of the firmware the device ran (as found in its IPSW), to name the "
            "kernel images of a panic."
        ),
    ] = None,
    kernel_signatures: Annotated[
        Optional[Path],
        typer.Option(
            help="Directory of `ipsw` kernel symbolication signatures (the `kernel` directory of "
            "https://github.com/blacktop/symbolicator), to name the kernel functions of a panic. "
            "Requires --kernelcache and the `ipsw` tool."
        ),
    ] = None,
) -> None:
    """
    Print an Apple crash report.

    Userland frames the report left unnamed are named when this host holds the Xcode DeviceSupport
    of the device and build the report came from.
    """
    if kernel_signatures is not None and kernelcache is None:
        raise typer.BadParameter("--kernel-signatures requires --kernelcache")
    report = get_crash_report_from_file(file)
    if kernelcache is not None and isinstance(report, KernelModeCrashReport):
        try:
            report.kernel_symbols = KernelSymbols.load(kernelcache, kernel_signatures)
        except OSError as e:
            raise typer.BadParameter(
                f"Reading the kernel symbols of {kernelcache} failed: {e}"
            ) from e
    # printed as a renderable, so colors follow the terminal: none when the output is piped
    Console(highlight=False).print(report, soft_wrap=True)


def cli() -> None:
    app()


if __name__ == "__main__":
    cli()
