from PyQt5.QtCore import QRegExp, QRegularExpressionMatch
from PyQt5.QtGui import QSyntaxHighlighter

from .styles import LIGHT_STYLES


class YaraHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for the Yara language.
    """
    keywords = [
        'import', 'include',
        'global', 'rule', 'meta', 'strings', 'condition',
        'all', 'any', 'none',
        'them',  
        'and', 'or', 'not',
        'false', 'true',
        'ascii', 'wide', 'base64', 'base64wide', 'fullword', 'nocase', 'xor', 'private',
        'uint8', 'uint8be', 'uint16', 'uint16be', 'uint32', 'uint32be',
        'icontains', 'iequals', 'matches',
        'int8', 'int8be', 'int16', 'int16be', 'int32', 'int32be',
        'startswith', 'istartswith', 'iendswith', 'endswith',
        'at', 'filesize', 'entrypoint', 'defined',
        'for', 'in', 'of',
    ]

    operators = [
        r'=',
        r'\band\b', r'\bor\b', r'\bnot\b',
        r'==', r'!=', r'<', r'<=', r'>', r'>=',
        r'\+', r'-', r'\*', r'/', r'\%',
        r'\^', r'\|', r'\&', r'\~', r'>>', r'<<',
    ]

    braces = [
        r'\{', r'\}', r'\(', r'\)', r'\[', r'\]',
    ]

    def __init__(self, document):
        QSyntaxHighlighter.__init__(self, document)

        rules = []

        rules += [(rf'\b{w}\b', 0, 'keyword') for w in YaraHighlighter.keywords]
        rules += [(o, 0, 'operator') for o in YaraHighlighter.operators]
        rules += [(b, 0, 'brace') for b in YaraHighlighter.braces]

        rules += [
            # 'rule' followed by an rule name
            (r'\brule\b\s*(\w+)', 1, 'rule'),

            # Numeric literals
            (r'\b[a-fA-F0-9]{2}\b', 0, 'numbers'),
            (r'\b[+-]?[0-9]+[lL]?\b', 0, 'numbers'),
            (r'\b[+-]?0[xX][0-9A-Fa-f]+[lL]?\b', 0, 'numbers'),
            (r'\b[+-]?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\b', 0, 'numbers'),

            # Wildcards
            (r'\b\?{2}\b', 0, 'numbers'),

            # Double-quoted string, possibly containing escape sequences
            (r'"[^"\\]*(\\.[^"\\]*)*"', 0, 'string'),

            # From '//' until a newline
            (r'//[^\n]*', 0, 'comment'),
        ]

        self.multiline_start = QRegExp(r'/\*')
        self.multiline_end = QRegExp(r'\*/')

        self.rules = [(QRegExp(pat), index, fmt) for (pat, index, fmt) in rules]

    @property
    def styles(self):
        return LIGHT_STYLES

    def highlightBlock(self, text):
        """Apply syntax highlighting to the given block of text.
        """
        # Do other syntax formatting
        for expression, nth, format in self.rules:
            index = expression.indexIn(text, 0)
            format = self.styles[format]

            while index >= 0:
                # We actually want the index of the nth match
                index = expression.pos(nth)
                length = len(expression.cap(nth))
                self.setFormat(index, length, format)
                index = expression.indexIn(text, index + length)

        self.setCurrentBlockState(0)
        self.match_multiline(text, 'string')

    def match_multiline(self, text, style):
        self.setCurrentBlockState(0)
        start_index = 0
        if self.previousBlockState() != 1:
            start_index = self.multiline_start.indexIn(text)

        while start_index >= 0:
            end_index = self.multiline_end.indexIn(text, start_index)
            if end_index == -1:
                self.setCurrentBlockState(1)
                length = len(text) - start_index
            else:
                pattern_length = len(self.multiline_end.pattern())
                length = end_index - start_index + pattern_length

            self.setFormat(start_index, length, self.styles[style])
            start_index = self.multiline_start.indexIn(text, start_index + length)
