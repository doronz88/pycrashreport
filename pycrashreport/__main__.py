from pathlib import Path
from typing import Annotated, Optional

import typer
from apple_symbols import KernelSymbols
from rich.console import Console

from pycrashreport.crash_report import (
    CrashReportBase,
    StackshotReportBase,
    get_crash_report_from_file,
    render_processes,
)

app = typer.Typer(add_completion=False)


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
            help="URL of a symbolicator-server to name userland and kernel frames with, instead of "
            "local DeviceSupport and --kernelcache. Requires `pycrashreport[remote]`."
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
    if server is not None and (
        kernelcache is not None or kernel_signatures is not None
    ):
        raise typer.BadParameter(
            "--server cannot be used with --kernelcache or --kernel-signatures"
        )
    report = get_crash_report_from_file(file)
    if server is not None:
        _use_server(report, server)
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


def _use_server(report: CrashReportBase, server: str) -> None:
    """Name the frames of the report with the symbols the server holds, where it has them."""
    try:
        from apple_symbols.remote import RemoteDeviceSymbols, RemoteKernelSymbols
        from symbolicator_server.client import SymbolicatorClient
        from symbolicator_server.exceptions import (
            IncompatibleServerError,
            ServerError,
            ServerUnreachableError,
        )
    except ImportError as e:
        raise typer.BadParameter(
            f"--server requires `pip install pycrashreport[remote]`: {e}"
        ) from e
    try:
        client = SymbolicatorClient.connect(server)
    except ServerUnreachableError as e:
        raise typer.BadParameter(f"{e.server} is unreachable: {e.reason}") from e
    except IncompatibleServerError as e:
        raise typer.BadParameter(
            f"{e.server} speaks API version {e.server_api}, this client {e.client_api}"
        ) from e
    except ServerError as e:
        raise typer.BadParameter(f"{server}: {e.message}") from e
    if report.product_type and report.build_version:
        try:
            report.device_support_symbols = RemoteDeviceSymbols.for_build(
                client, report.product_type, report.build_version
            )
        except LookupError as e:
            typer.echo(f"warning: {e}", err=True)
    if isinstance(report, StackshotReportBase) and report.kernelcache_uuid:
        try:
            report.kernel_symbols = RemoteKernelSymbols.for_kernelcache(
                client, report.kernelcache_uuid
            )
        except LookupError as e:
            typer.echo(f"warning: {e}", err=True)


def cli() -> None:
    app()


if __name__ == "__main__":
    cli()
