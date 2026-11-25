"""Symbol sources which ask several others in turn, so what one cannot name the next may."""

from typing import List, Optional, Sequence, Tuple

from apple_symbols import (
    KernelImage,
    KernelSymbolSource,
    SymbolImage,
    UserlandSymbolSource,
)


class SymbolServerError(Exception):
    """A symbolicator server could not be asked for symbols."""


class UserlandSymbolChain:
    """Userland symbols of several sources of the same device and build, the first one first."""

    def __init__(self, sources: Sequence[UserlandSymbolSource]) -> None:
        self.sources = list(sources)
        by_uuid = {}
        for source in self.sources:
            for image in source.images:
                by_uuid.setdefault(image.uuid, image)
        self.images: List[SymbolImage] = sorted(
            by_uuid.values(), key=lambda image: image.vmaddr
        )

    @property
    def has_shared_cache_images(self) -> bool:
        return any(source.has_shared_cache_images for source in self.sources)

    @property
    def shared_cache_base(self) -> Optional[int]:
        for source in self.sources:
            base = source.shared_cache_base
            if base is not None:
                return base
        return None

    def image_by_uuid(self, image_uuid: str) -> Optional[SymbolImage]:
        for source in self.sources:
            image = source.image_by_uuid(image_uuid)
            if image is not None:
                return image
        return None

    def image_by_address(self, address: int) -> Optional[SymbolImage]:
        for source in self.sources:
            image = source.image_by_address(address)
            if image is not None:
                return image
        return None

    def symbolicate(
        self, image: SymbolImage, address: int
    ) -> Optional[Tuple[str, int]]:
        for source in self.sources:
            # every source knows an image as its own object, at its own address
            own = source.image_by_uuid(image.uuid)
            if own is None:
                continue
            symbol = source.symbolicate(own, address - image.vmaddr + own.vmaddr)
            if symbol is not None:
                return symbol
        return None


class KernelSymbolChain:
    """Kernel symbols of several sources of the same kernelcache, the first one first."""

    def __init__(self, sources: Sequence[KernelSymbolSource]) -> None:
        self.sources = list(sources)
        by_uuid = {}
        for source in self.sources:
            for image in source.images:
                by_uuid.setdefault(image.uuid, image)
        self.images: List[KernelImage] = list(by_uuid.values())

    @property
    def has_symbols(self) -> bool:
        return any(source.has_symbols for source in self.sources)

    def image_by_uuid(self, image_uuid: str) -> Optional[KernelImage]:
        for source in self.sources:
            image = source.image_by_uuid(image_uuid)
            if image is not None:
                return image
        return None

    def symbolicate(self, address: int) -> Optional[Tuple[str, int]]:
        for source in self.sources:
            symbol = source.symbolicate(address)
            if symbol is not None:
                return symbol
        return None
