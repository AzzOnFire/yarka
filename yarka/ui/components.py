from .highlighter import YaraHighlighter

from .PyQt import QtGui, QtWidgets, QtCore


class Checkbox(QtWidgets.QCheckBox):
    def __init__(
            self,
            label: str,
            default: bool = False,
            on_click = None):
        super().__init__(label)
        
        self.setCheckState(QtCore.Qt.Checked if default else QtCore.Qt.Unchecked)
        if on_click:
            self.clicked.connect(on_click)

    def is_checked(self) -> bool:
        return self.checkState() == QtCore.Qt.Checked


class Button(QtWidgets.QPushButton):
    def __init__(self, label: str, on_click = None):
        super().__init__(label)

        self.setFixedWidth(100)
        if on_click:
            self.clicked.connect(on_click)


class NumberInput(QtWidgets.QSpinBox):
    def __init__(
            self,
            default: int = None,
            min_value: int = 0,
            max_value: int = 100,
            step: int = 1,
            on_change = None):

        super().__init__()
        self.setSingleStep(step)
        self.setFixedWidth(48)
        self.setRange(min_value, max_value)
        if default and ((default - min_value) % step == 0):
            self.setValue(default)
        if on_change:
            self.valueChanged.connect(on_change)


class Label(QtWidgets.QLabel):
    pass


class YaraTextEdit(QtWidgets.QPlainTextEdit):
    smarten_punctuation = QtCore.pyqtSignal()

    def __init__(self, default: str, highlighting: bool = True):
        super().__init__(None)

        if highlighting:
            self.highlighter = YaraHighlighter(self.document())

        font = QtGui.QFont()
        font.setFamily("Consolas")
        font.setStyleHint(QtGui.QFont.Monospace)
        font.setFixedPitch(True)
        font.setPointSize(10)
        self.setFont(font)

        metrics = QtGui.QFontMetrics(font)
        self.setTabStopDistance(4 * metrics.horizontalAdvance(' '))
        self.set_content(default)

    def set_content(self, text: str):
        self.setPlainText(text)

    def contextMenuEvent(self, ev):
        m = self.createStandardContextMenu()
        m.addSeparator()
        m.addAction('Smarten punctuation', self.smarten_punctuation.emit)
        m.exec(ev.globalPos())
