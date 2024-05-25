from collections import UserList
import inspect
import re
from typing import Any, Dict, List, Union, Optional, Iterable, Callable
import textwrap

from .wrappers import YaraEntity


class RuleBuilder(object):
    def __init__(
            self, 
            name: str,
            show_comments: bool = True,
            strict: bool = False,
            indent: int = 2,
            indent_headers: bool = False,
            wrap_curly_brace: bool = False,
        ):
        self.name = self._escape_name(name)

        self.show_comments = show_comments
        self.strict = strict
        self.indent = indent
        self.indent_headers = indent_headers
        self.wrap_curly_brace = wrap_curly_brace

        self.meta: Dict[str, Union[str, Callable]] = {}
        self.strings: Dict[str, YaraEntity] = {}
        self.conditions: List[Union[str, Callable]] = []

    def _escape_name(self, name) -> str:
        _name = ''.join(x if x.isalnum() else '_' for x in name)
        _name = _name.replace('__', '_')

        # hack for 80 symbols limit
        if len(_name) >= 80:
            _name = _name[:38] + '__' + _name[-38:]

        return _name

    def add_meta(self, name: str, value: Union[str, Callable]):
        if not any((isinstance(value, str), callable(value))):
            raise TypeError('Meta value must be str or callable object')

        if callable(value) and len(inspect.signature(value).parameters):
            raise TypeError('Callable meta value can take only 0 arguments')

        self.meta[name] = value
        return self

    def add_string(self, name, value: YaraEntity):
        self.strings[name] = value
        return self

    def add_condition(self, condition: Union[str, Callable]):
        if not any((isinstance(condition, str), callable(condition))):
            raise TypeError('Condition must be str or callable object')

        if callable(condition):
            if len(inspect.signature(condition).parameters) > 2:
                raise TypeError('Callable condition can take 0 or 1 arguments')

        self.conditions.append(condition)
        return self

    def build(self):
        sanitized_name = self.sanitize_rule_name(self.name)
        result = f"rule {sanitized_name}"
        result += '\n' if self.wrap_curly_brace else ' '
        result += '{\n'

        content = ''
        content += self.build_meta()
        content += self.build_strings()
        content += self.build_condition()
        
        result += self._indent(content) if self.indent_headers else content
        result += "}\n"
        return result

    def build_meta(self):
        result = "meta:\n"
        for key, value in self.meta.items():
            _value = value() if callable(value) else value
            result += self._indent(f'{key} = "{_value}"')
            result += '\n'
        result += "\n"
        return result

    def build_strings(self):
        result = "strings:\n"
        for key, value in self.strings.items():
            content = value.build(
                show_comments=self.show_comments,
                strict=self.strict,
                indent=self.indent,
            )
            result += self._indent(f'${key} = {content}')
            result += '\n'
        result += "\n"
        return result

    def build_condition(self) -> str:
        result = "condition:\n"
        total = []
        for value in self.conditions:
            if callable(value):
                args = inspect.signature(value).parameters
                if len(args) == 0:
                    _value = value()
                elif len(args) == 1:
                    _value = value(len(self.strings))
            else:
                _value = value

            if _value:
                total.append(str(_value))

        result += '\nand '.join(total)
        result += '\n'

        return self._indent(result).lstrip()

    def is_empty(self) -> bool:
        return len(self.strings) == 0

    @classmethod
    def is_rule_name_valid(cls, name: str) -> bool:
        return cls.sanitize_rule_name(name) == name

    @staticmethod
    def sanitize_rule_name(name: str) -> str:
        name = re.sub(r'[^0-9a-zA-Z_]+', '_', name)

        # check name starts with any digit
        if re.match(r'^\d', name):             
            name = f'_{name}'

        if len(name) <= 3:
            raise ValueError(f'Sanitized rule name "{name}" less than 3 chars')
        return name

    def _indent(self, value: str) -> str:
        prefix = ' ' * self.indent
        return textwrap.indent(value, prefix=prefix)

    def _build_entity(self, entity: YaraEntity) -> str:
        content = entity.build(
            show_comments=self.show_comments,
            strict=self.strict,
            indent=self.indent,
        )

        return content


class RulesetBuilder(UserList):
    def __init__(self, rules: Optional[Iterable[RuleBuilder]] = None):
        if not rules:
            rules = list()

        super().__init__(rules)

    def build(self) -> str:
        rules = [rule.build() for rule in iter(self)]

        return '\n\n'.join(rules)

    def __setattr__(self, name: str, value: Any):
        if name in {'show_comments', 'strict', 'indent', 'indent_headers'}:
            for rule in iter(self):
                setattr(rule, name, value)
        else:
            super().__setattr__(name, value)
