from pathlib import Path
from typing import Annotated, Optional

import typer
from apple_symbols import KernelSymbols
from rich.console import Console
from symbolicator_server.client import SymbolicatorClient
from symbolicator_server.exceptions import (
    IncompatibleServerError,
    ServerError,
    ServerUnreachableError,
)
from symbolicator_server.ips_report import IpsReport

from pycrashreport.crash_report import (
    StackshotReportBase,
    get_crash_report_from_file,
    render_processes,
)

app = typer.Typer(add_completion=False)


def symbolicate_on_server(server: str, report_path: Path) -> IpsReport:
    """Symbolicate the report stored at ``report_path`` on a symbolicator server."""
    if not report_path.is_file():
        raise typer.BadParameter("--server requires the report as a file")

    try:
        symbolicated = SymbolicatorClient.connect(server).symbolicate(report_path)
    except IncompatibleServerError as e:
        raise typer.BadParameter(
            f"{e.server} speaks API version {e.server_api}, this client speaks {e.client_api}"
        ) from e
    except ServerUnreachableError as e:
        raise typer.BadParameter(f"Reaching {e.server} failed: {e.reason}") from e
    except ServerError as e:
        raise typer.BadParameter(
            f"Symbolicating on {server} failed: {e.message}"
        ) from e
    return IpsReport.from_dict(symbolicated)


@app.command()
def main(
    file: Annotated[typer.FileText, typer.Argument()],
    kernelcache: Annotated[
        Optional[Path],
        typer.Option(
            help="Kernelcache of the firmware the device ran (as found in its IPSW), to name the "
            "kernel images of a panic or a stackshot."
        ),
    ] = None,
    kernel_signatures: Annotated[
        Optional[Path],
        typer.Option(
            help="Directory of `ipsw` kernel symbolication signatures (the `kernel` directory of "
            "https://github.com/blacktop/symbolicator), to name the kernel functions of a panic or a stackshot. "
            "Requires --kernelcache and the `ipsw` tool."
        ),
    ] = None,
    server: Annotated[
        Optional[str],
        typer.Option(
            "--server",
            "-s",
            envvar="SYMBOLICATOR_SERVER",
            help="URL of a symbolicator server (https://github.com/netanelc305/symbolicator-server), "
            "e.g. http://localhost:3993, to name the frames of a panic or a stackshot with in place "
            "of the local kernelcache and Xcode DeviceSupport.",
        ),
    ] = None,
    process: Annotated[
        Optional[list[str]],
        typer.Option(
            "--process",
            "-p",
            help="Name or pid of a process of a panic, a stackshot or a spindump report to print "
            "the call stacks of. "
            "May be given several times.",
        ),
    ] = None,
    all_processes: Annotated[
        bool,
        typer.Option(
            "--all",
            help="Print the call stacks of every process of a panic, a stackshot or a spindump report, "
            "or of every thread of a crash.",
        ),
    ] = False,
    running: Annotated[
        bool,
        typer.Option(
            "--running",
            "-r",
            help="Print the threads of a panic or a stackshot which were on a CPU.",
        ),
    ] = False,
) -> None:
    """
    Print an Apple crash report.

    Userland frames the report left unnamed are named when this host holds the Xcode DeviceSupport
    of the device and build the report came from.
    """
    if kernel_signatures is not None and kernelcache is None:
        raise typer.BadParameter("--kernel-signatures requires --kernelcache")
    if server is not None and kernelcache is not None:
        raise typer.BadParameter("--server names the kernel frames, drop --kernelcache")
    report = get_crash_report_from_file(file)
    if server is not None:
        # the server holds the symbols, the host's are not looked up
        report.device_support_symbols = None
        if isinstance(report, StackshotReportBase):
            report.server_report = symbolicate_on_server(server, Path(file.name))
    if kernelcache is not None and isinstance(report, StackshotReportBase):
        try:
            report.kernel_symbols = KernelSymbols.load(kernelcache, kernel_signatures)
        except OSError as e:
            raise typer.BadParameter(
                f"Reading the kernel symbols of {kernelcache} failed: {e}"
            ) from e
    try:
        processes = render_processes(report, process or [], all_processes, running)
    except ValueError as e:
        raise typer.BadParameter(str(e)) from e
    # printed as a renderable, so colors follow the terminal: none when the output is piped
    console = Console(highlight=False)
    console.print(report, soft_wrap=True)
    if processes is not None:
        console.print(processes, soft_wrap=True)


def cli() -> None:
    app()


if __name__ == "__main__":
    cli()
