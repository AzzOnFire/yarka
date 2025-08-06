from .PyQt import QtGui


def format(color, style=''):
    """
    Return a QTextCharFormat with the given attributes.
    """
    _color = QtGui.QColor()
    _color.setNamedColor(color)

    _format = QtGui.QTextCharFormat()
    _format.setForeground(_color)
    if 'bold' in style:
        _format.setFontWeight(QtGui.QFont.Weight.Bold)
    if 'italic' in style:
        _format.setFontItalic(True)

    return _format


class LightThemeColors:
    Red = "#B71C1C"
    Pink = "#FCE4EC"
    Purple = "#4A148C"
    DeepPurple = "#311B92"
    Indigo = "#1A237E"
    Blue = "#0D47A1"
    LightBlue = "#01579B"
    Cyan = "#006064"
    Teal = "#004D40"
    Green = "#1B5E20"
    LightGreen = "#33691E"
    Lime = "#827717"
    Yellow = "#F57F17"
    Amber = "#FF6F00"
    Orange = "#E65100"
    DeepOrange = "#BF360C"
    Brown = "#3E2723"
    Grey = "#212121"
    BlueGrey = "#263238"


LIGHT_STYLES = {
    'keyword': format(LightThemeColors.LightBlue, 'bold'),
    'operator': format(LightThemeColors.Red, 'bold'),
    'brace': format(LightThemeColors.Purple),
    'rule': format(LightThemeColors.Indigo, 'bold'),
    'string': format(LightThemeColors.Amber),
    'comment': format(LightThemeColors.Green, 'italic'),
    'numbers': format(LightThemeColors.Grey),
    'wildcard': format(LightThemeColors.Blue),
}
