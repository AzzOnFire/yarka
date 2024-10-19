from typing import Generator, Iterable, Union

from .types import String, Instruction
from .wrappers import YaraEntity, YaraBytes, YaraInstructions, YaraString


class YaraExtractor(object):
    def __init__(self, iterable: Iterable[Union[bytes, Instruction, String]]):
        self.iterable = iterable

    @staticmethod
    def _filter_byte_sequence(current_type, sequence: list) -> bool:
        if current_type is not int:
            return False

        stripped = bytes(sequence).strip(b'\x00')
        return len(stripped) > 3

    def __iter__(self) -> Generator[YaraEntity, None, None]:
        current_type = None
        sequence = []

        for entity in self.iterable:
            if not entity and entity != 0x00:
                continue

            if current_type is not type(entity):
                if current_type is Instruction:
                    yield YaraInstructions(sequence)
                elif self._filter_byte_sequence(current_type, sequence):
                    yield YaraBytes(sequence)

                sequence.clear()
                current_type = type(entity)

            if isinstance(entity, String):
                if len(YaraString.escape(str(entity))) > 4:
                    yield YaraString.from_object(entity)
            else:
                sequence.append(entity)

        if sequence:
            if current_type is Instruction:
                yield YaraInstructions(sequence)
            elif self._filter_byte_sequence(current_type, sequence):
                yield YaraBytes(sequence)
