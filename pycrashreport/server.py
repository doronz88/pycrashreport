"""
Symbols of a symbolicator server.

https://github.com/netanelc305/symbolicator-server holds the symbols of scanned IPSWs, so a report
is named without the Xcode DeviceSupport or the kernelcache of its device on this host. A report
asks the server of its ``symbol_server``, which ``PYCRASHREPORT_SERVER`` sets for every report.
"""

import logging
from typing import Iterable, Optional

from apple_symbols.remote import RemoteDeviceSymbols, RemoteKernelSymbols
from symbolicator_server.client import SymbolicatorClient
from symbolicator_server.exceptions import (
    IncompatibleServerError,
    ServerError,
    ServerUnreachableError,
)

from pycrashreport.symbols import SymbolServerError

logger = logging.getLogger(__name__)


def connect(server: str) -> SymbolicatorClient:
    """
    Get a client of the server at the given URL, e.g. ``http://localhost:3993``.

    :raises SymbolServerError: If the server cannot be reached, or does not tell its routes.
    """
    try:
        return SymbolicatorClient.connect(server)
    except ServerUnreachableError as e:
        raise SymbolServerError(f"Reaching {e.server} failed: {e.reason}") from e
    except IncompatibleServerError as e:
        raise SymbolServerError(
            f"{e.server} speaks version {e.server_api} of {e.route}, not {e.client_api} as "
            f"the installed symbolicator-server does"
        ) from e
    except ServerError as e:
        raise SymbolServerError(f"{server} failed: {e.message}") from e


def userland_symbols(
    client: SymbolicatorClient, product_type: str, build_version: str
) -> Optional[RemoteDeviceSymbols]:
    """Get the userland symbols of a device and build, ``None`` when the server holds none."""
    try:
        return RemoteDeviceSymbols.for_build(client, product_type, build_version)
    except LookupError:
        logger.warning(
            f"{client.server} holds no symbols of {product_type} ({build_version}), "
            f"scan its IPSW to name user frames with it"
        )
        return None


def kernel_symbols(
    client: SymbolicatorClient, kernelcache_uuid: str
) -> Optional[RemoteKernelSymbols]:
    """Get the symbols of a kernelcache, ``None`` when the server does not hold it."""
    try:
        symbols = RemoteKernelSymbols.for_kernelcache(client, kernelcache_uuid)
    except LookupError:
        symbols = None
    # the server answers with no images for a UUID it knows as something else
    if symbols is None or not symbols.images:
        logger.warning(
            f"{client.server} does not hold the kernelcache {kernelcache_uuid}, "
            f"scan its IPSW to name kernel frames with it"
        )
        return None
    return symbols


def kernel_symbols_of_build(
    client: SymbolicatorClient,
    product_type: str,
    build_version: str,
    image_uuids: Iterable[str],
) -> Optional[RemoteKernelSymbols]:
    """
    Get the symbols of the kernelcache of a device and build which holds the given kernel images,
    for a report which does not tell its kernelcache. ``None`` when the server holds none.
    """
    try:
        return RemoteKernelSymbols.for_build(
            client, product_type, build_version, image_uuids
        )
    except LookupError:
        logger.warning(
            f"{client.server} holds no kernelcache of {product_type} ({build_version}) with "
            f"the kernel images of the report, scan its IPSW to name kernel frames with it"
        )
        return None
