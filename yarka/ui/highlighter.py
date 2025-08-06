from .PyQt import QtCore, QtGui

from .styles import LIGHT_STYLES


class YaraHighlighter(QtGui.QSyntaxHighlighter):
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
        super().__init__(document)

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

        self.multiline_start = QtCore.QRegularExpression(r'/\*')
        self.multiline_end = QtCore.QRegularExpression(r'\*/')

        self.rules = [(QtCore.QRegularExpression(pat), index, fmt) for (pat, index, fmt) in rules]

    @property
    def styles(self):
        return LIGHT_STYLES

    def highlightBlock(self, text):
        """Apply syntax highlighting to the given block of text.
        """
        # Do other syntax formatting
        for expression, nth, fmt in self.rules:
            fmt = self.styles[fmt]

            iterator = expression.globalMatch(text, 0)
            while iterator.hasNext():
                # We actually want the index of the nth match
                match = iterator.next()
                self.setFormat(
                    match.capturedStart(nth), 
                    match.capturedLength(nth),
                    fmt
                )

        self.setCurrentBlockState(0)
        self.match_multiline(text, self.styles['string'])

    def match_multiline(self, text, fmt):
        start_index = 0
        if self.previousBlockState() == 1:
            # Inside a multi-line comment
            end_match = self.multiline_end.match(text)
            if end_match.hasMatch():
                length = end_match.capturedEnd() - start_index
                self.setFormat(start_index, length, fmt)
                start_index = end_match.capturedEnd()
                self.setCurrentBlockState(0)
            else:
                self.setFormat(start_index, len(text), fmt)
                self.setCurrentBlockState(1)
                return

        start_match = self.multiline_start.match(text, start_index)
        while start_match.hasMatch():
            end_match = self.multiline_end.match(text, start_match.capturedEnd())
            if end_match.hasMatch():
                length = end_match.capturedEnd() - start_match.capturedStart()
                self.setFormat(start_match.capturedStart(), length, fmt)
                start_index = end_match.capturedEnd()
            else:
                self.setFormat(start_match.capturedStart(), len(text) - start_match.capturedStart(), fmt)
                self.setCurrentBlockState(1)
                return
            start_match = self.multiline_start.match(text, start_index)
