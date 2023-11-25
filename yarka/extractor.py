from typing import Generator, Optional, Union

from . import utils
from .types import Instruction, String

import idautils
import idaapi
import ida_funcs


class RangeExtractor(object):
    def __init__(self, start, end):
        self.ea = start
        self.end = end

    def _process_insn(self) -> Optional[Instruction]:
        entity = Instruction.from_ea(self.ea)
        if entity is None:
            return None

        self.ea += entity.size
        return entity

    def _process_string(self) -> Optional[String]:
        entity = String.from_ea(self.ea)
        if entity is None:
            return None

        self.ea += entity.size
        return entity

    def _process_byte(self) -> Optional[int]:
        x = idaapi.get_byte(self.ea)
        self.ea += 1
        return x

    def __iter__(self) -> Generator[Union[bytes, String, Instruction], None, None]:
        while self.ea < self.end:
            if not idaapi.is_loaded(self.ea):
                self.ea += 1
                continue
                
            if idaapi.is_code(idaapi.get_flags(self.ea)):
                insn = self._process_insn()
                if insn:
                    yield insn
                    continue
            elif idaapi.is_data(idaapi.get_flags(self.ea)):
                string = self._process_string()
                if string:
                    yield string
                    continue

            yield self._process_byte()


class DataRefsExtractor():
    def __init__(self, ea):
        self.ea = ea

    @staticmethod
    def get_ref_data(ea: int):
        _ea = utils.resolve_ptr_until_data(ea)

        entity = String.from_ea(_ea)
        if entity:
            yield entity
        elif idaapi.is_loaded(_ea):
            yield from idaapi.get_bytes(_ea, 8)

    def __iter__(self) -> Generator[Union[bytes, String], None, None]:
        for ref in idautils.DataRefsFrom(self.ea):
            yield from self.get_ref_data(ref)


class FunctionExtractor():
    def __init__(self, ea, block_min_size: int = 16):
        self.function = ida_funcs.get_func(ea)
        if self.function is None:
            raise ValueError(f'No function at 0x{ea:08X}')

        self.block_min_size = block_min_size

    def __iter__(self) -> Generator[Union[bytes, String, Instruction], None, None]:
        blocks = idaapi.FlowChart(self.function)

        for block in blocks:
            size = block.end_ea - block.start_ea
            if size >= self.block_min_size:
                for entity in RangeExtractor(block.start_ea, block.end_ea):
                    if isinstance(entity, Instruction):
                        yield entity

            for ea in range(block.start_ea, block.end_ea):
                yield from DataRefsExtractor(ea)
