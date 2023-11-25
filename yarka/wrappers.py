from abc import abstractmethod
from typing import List, Optional, Iterable

from .types import String, Instruction


class YaraEntity(object):
    @abstractmethod
    def build(self, **kwargs) -> str:
        pass


class YaraString(YaraEntity):
    def __init__(self, data: str, modifiers: Optional[list] = None):
        self.data: str = self.escape(data)
        self.modifiers = modifiers if modifiers else list()

    @staticmethod
    def escape(string: str) -> str:
        stripped = str(string).strip('\r\n')
        escaped = repr(stripped)[1:-1]
        return escaped.replace('"', '\\\"')

    @classmethod
    def from_object(cls, string: String):
        modifiers = []
        if string.bytes_per_char == 2:
            modifiers.append('wide')

        converted = str(string)
        if converted.strip('\r\n') == converted:
            modifiers.append('fullword')

        return cls(converted, modifiers)

    def build(self, **kwargs) -> str:
        modifiers = ' '.join(self.modifiers)
        result = f'"{self.data}"'
        if modifiers:
            result += f' {modifiers}'

        return result

    def __hash__(self) -> int:
        return hash(tuple(map(str, self.entities)))

    def __eq__(self, other: "YaraString") -> bool:
        return self.data == other.data

    def __str__(self) -> str:
        return self.data

    def __repr__(self) -> str:
        return f'<YaraString "{self.data}">'


class YaraInstructions(YaraEntity):
    def __init__(self, entities: Iterable[Instruction]):
        self.entities: List[Instruction] = list(entities)

    def build(
            self,
            show_comments: bool = True,
            strict: bool = False,
            indent: int = 2,
            **kwargs) -> str:

        if len(self.entities) == 1:
            insn = self.entities[0]
            data = insn.escape(escape_relative=not strict)

            return f"{{ {data} }}" 

        result = '{\n'
        for insn in self.entities:
            data = insn.escape(escape_relative=not strict)

            result += ' ' * indent
            if show_comments:
                comment = str(insn)
                comment = f'{comment[:48]}...' if len(comment) > 48 else comment
                result += f'{data:30} // {comment}'
            else:
                result += data
            result += '\n'

        result += '}'
        return result

    def __hash__(self) -> int:
        return hash(tuple(map(str, self.entities)))

    def __eq__(self, other: "YaraInstructions") -> bool:
        return tuple(self.entities) == tuple(other.entities)

    def __len__(self) -> int:
        return len(self.entities)

    def __str__(self) -> str:
        mnemonics = [str(insn) for insn in self.entities]
        return ''.join(mnemonics)

    def __repr__(self) -> str:
        data = ' '.join([insn.mnemonic for insn in self.entities])
        return f'<YaraInstructions "{data}">'
               

class YaraBytes(YaraEntity):
    def __init__(self, data: bytes):
        self.data = bytes(data)

    def build(self, indent: int = 2, **kwargs) -> str:

        if len(self.data) <= 16:
            data = self.data.hex(' ').upper()
            return f"{{ {data} }}" 

        result = '{\n'
        for i in range(0, len(self.data), 16):
            data = self.data[i:i + 16].hex(' ').upper()
            result += ' ' * indent
            result += data
            result += '\n'
        result += '}'
        return result

    def __hash__(self) -> int:
        return hash(self.data)

    def __eq__(self, other: "YaraString") -> bool:
        return self.data == other.data

    def __len__(self) -> int:
        return len(self.data)

    def __str__(self) -> str:
        return self.data.hex(' ')

    def __repr__(self) -> str:
        data = self.data[:10].hex(' ')
        return f'<YaraBytes "{data}">'
