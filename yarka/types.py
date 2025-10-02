from typing import Optional, List

import idaapi
import idc
import ida_nalt
import ida_strlist
import ida_bytes


class Operand(object):
    def __init__(self, operand: idaapi.op_t):
        self.operand = operand

    def has_immediate_value(self) -> bool:
        return self.operand.type == idaapi.o_imm

    def has_relative_value(self) -> bool:
        return self.operand.type in {
            idaapi.o_far, idaapi.o_near, idaapi.o_mem, idaapi.o_displ
        }
         
    def is_empty(self) -> bool:
        return self.operand.type == idaapi.o_void
                                                       
    @property
    def value(self) -> int:
        if self.operand.addr:
            value = self.operand.addr & 0xFFFFFFFF
            is_signed = value & 0xF0000000
            return value - 2 ** 32 if is_signed else value

        return self.operand.value

    @property
    def byte_offset(self) -> int:
        return self.operand.offb


class Instruction(object):
    def __init__(self, insn: idaapi.insn_t):
        self.insn = insn

    @classmethod
    def from_ea(cls, ea) -> Optional["Instruction"]:
        insn = idaapi.insn_t()
        length = idaapi.decode_insn(insn, ea)
        if not length:
            return None

        return cls(insn)
    
    def __eq__(self, other: "Instruction") -> bool:
        return str(self) == str(other)

    @property
    def mnemonic(self) -> str:
        return self.insn.get_canon_mnem()

    @property
    def size(self) -> int:
        return self.insn.size
    
    @property
    def address(self) -> int:
        return self.insn.ea
    
    @property
    def bytes(self) -> bytes:
        return idaapi.get_bytes(self.insn.ea, self.insn.size)
    
    @property
    def operands(self) -> List[Operand]:
        total = [Operand(op) for op in self.insn.ops]
        return [op for op in total if not op.is_empty()]

    def escape(
            self,
            escape_immediate: bool = False,
            escape_relative: bool = True) -> str:

        data = self.bytes.hex(' ').split()
        
        operands = self.operands
        for i, op in enumerate(operands):
            if escape_relative and op.has_relative_value():
                pass
            elif escape_immediate and op.has_immediate_value():
                pass
            else:
                continue

            start = op.byte_offset
            if i != len(operands) - 1:
                next_start = operands[i + 1].byte_offset
                end = min(next_start, self.insn.size)
            else:
                end = self.insn.size

            if all((start, end)):
                data[start:end] = ['??'] * (end - start)

        return ' '.join(data)

    def comment(self, max_length: int = 48) -> str:
        flags = idaapi.GENDSM_REMOVE_TAGS
        comment = idaapi.generate_disasm_line(self.address, flags)
        if len(comment) <= max_length:
            return comment

        return f'{comment[:48]}...'

    def __str__(self) -> str:
        return self.comment()
    
    def __repr__(self) -> str:
        insn = ' '.join(str(self).split())
        return f'<Insn "{insn}">'


class String(object):
    def __init__(self, ea: int, string: str, bytes_per_char: int = 1):
        self.ea = ea
        self.string = string.decode() if hasattr(string, 'decode') else string
        self.bytes_per_char = bytes_per_char

    @staticmethod
    def symbol_size_by_type(str_type: int):
        return {
            ida_nalt.STRTYPE_C: 1,
            ida_nalt.STRTYPE_C_16: 2,
            ida_nalt.STRTYPE_PASCAL: 2,
            ida_nalt.STRTYPE_C_32: 4,
            0x2000001: 2,
        }.get(str_type, 1)

    @classmethod
    def from_string_info(cls, info: ida_strlist.string_info_t) -> Optional["String"]:
        string = ida_bytes.get_strlit_contents(info.ea, info.length, info.type)
        if not string:
            return None

        bytes_per_char = cls.symbol_size_by_type(info.type)

        return cls(info.ea, string.decode(), bytes_per_char)

    @classmethod
    def from_ea(cls, ea) -> Optional["String"]:
        str_type = idc.get_str_type(ea)
        if str_type is None:
            return None

        string = idc.get_strlit_contents(ea, strtype=str_type)
        if not string:
            return None

        bytes_per_char = cls.symbol_size_by_type(str_type)

        return cls(ea, string.decode(), bytes_per_char)

    def __eq__(self, other: "String") -> bool:
        return str(self) == str(other)

    def __str__(self) -> str:
        return self.string
    
    def __repr__(self) -> str:
        return f'<String "{str(self)}">'

    def __len__(self) -> int:
        return len(str(self))

    @property
    def size(self) -> int:
        return len(self) * self.bytes_per_char
    
    @property
    def address(self) -> int:
        return self.ea
    
    def __bytes__(self) -> bytes:
        return idaapi.get_bytes(self.ea, self.size)
