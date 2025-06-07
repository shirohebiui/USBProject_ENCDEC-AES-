
from PyQt5.QtWidgets import (
    QWidget, QTextEdit, QLineEdit, QPushButton,
    QHBoxLayout, QVBoxLayout
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QDragEnterEvent, QDropEvent

from AES import enc_aes, dec_aes

class EncryptWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)

        self.left_file_paths = []
        self.right_file_paths = []

        self.file_status_1 = QTextEdit()
        self.file_status_1.setPlaceholderText("왼쪽에 원본 파일을 드래그 하세요")
        self.file_status_1.setReadOnly(True)

        self.file_status_2 = QTextEdit()
        self.file_status_2.setPlaceholderText("오른쪽에 암호화된 파일을 드래그 하세요")
        self.file_status_2.setReadOnly(True)

        self.key_input = QLineEdit("a1c3e9f207b64d58")
        self.key_input.setPlaceholderText("KEY 값을 입력하세요")

        self.encrypt_btn = QPushButton("암호화")
        self.decrypt_btn = QPushButton("복호화")

        self.encrypt_btn.clicked.connect(self.run_encrypt)
        self.decrypt_btn.clicked.connect(self.run_decrypt)

        top_layout = QHBoxLayout()
        top_layout.addWidget(self.file_status_1)
        top_layout.addWidget(self.file_status_2)

        bottom_layout = QHBoxLayout()
        bottom_layout.addWidget(self.key_input)
        bottom_layout.addStretch()
        bottom_layout.addWidget(self.encrypt_btn)
        bottom_layout.addWidget(self.decrypt_btn)

        main_layout = QVBoxLayout()
        main_layout.addLayout(top_layout)
        main_layout.addLayout(bottom_layout)

        self.setLayout(main_layout)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        paths = [url.toLocalFile() for url in event.mimeData().urls()]
        x_pos = event.pos().x()
        mid = self.width() // 2

        if x_pos < mid:
            self.left_file_paths = paths
            self.file_status_1.setText("왼쪽 드롭된 파일:\n" + "\n".join(paths))
        else:
            self.right_file_paths = paths
            self.file_status_2.setText("오른쪽 드롭된 파일:\n" + "\n".join(paths))

    def run_encrypt(self):
        key = self.key_input.text()
        if not self.left_file_paths:
            self.file_status_1.setText("왼쪽에 파일을 먼저 드래그하세요.")
            return
        if not key:
            self.file_status_1.setText("KEY 값을 입력하세요.")
            return

        self.right_file_paths = enc_aes(self.left_file_paths, key)
        self.file_status_2.setText("암호화 완료:\n" + "\n".join(self.right_file_paths))

    def run_decrypt(self):
        key = self.key_input.text()
        if not self.right_file_paths:
            self.file_status_2.setText("오른쪽에 파일을 먼저 드래그하세요.")
            return
        if not key:
            self.file_status_2.setText("KEY 값을 입력하세요.")
            return

        self.left_file_paths = dec_aes(self.right_file_paths, key)
        self.file_status_1.setText("복호화 완료:\n" + "\n".join(self.left_file_paths))
