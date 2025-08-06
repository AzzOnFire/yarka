from .PyQt import QtWidgets, QtCore

from .components import Button


class ClosableDialog(QtWidgets.QDialog):
    def __init__(
            self,
            title: str = 'Dialog',
            width: int = 800,
            heihgt: int = 600,
            top_left_items: list = None,
            top_right_items: list = None,
            body_items: list = None
        ):

        super().__init__(None)
        self.setWindowTitle(title)
        self.resize(width, heihgt)
        self._build_dialog(top_left_items, top_right_items, body_items)

    def handle_close_click(self):
        self.close()

    def _build_dialog(self, top_left: list, top_right: list, body: list):
        self.close_btn = Button("OK", self.handle_close_click)

        self.top_layout = QtWidgets.QHBoxLayout()
        for element in top_left:
            self.top_layout.addWidget(element)
        self.top_layout.addStretch()
        for element in top_right:
            self.top_layout.addWidget(element)

        self.layout = QtWidgets.QVBoxLayout(self)
        self.layout.addLayout(self.top_layout)

        for element in body:
            self.layout.addWidget(element)

        self.bottom_layout = QtWidgets.QHBoxLayout()
        self.bottom_layout.setAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignBottom)
        self.bottom_layout.addWidget(self.close_btn)
        self.layout.addLayout(self.bottom_layout)
