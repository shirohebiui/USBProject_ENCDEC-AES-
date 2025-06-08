
from PyQt5.QtWidgets import (
    QWidget, QTextEdit, QLineEdit, QPushButton,
    QHBoxLayout, QVBoxLayout, QLabel, QMessageBox
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QDragEnterEvent, QDropEvent
from AES import enc_aes, dec_aes, isValidDec
import os

class EncryptWidget(QWidget):
    def __init__(self, aes_key):
        super().__init__()
        self.setAcceptDrops(True)
        self.aes_key = aes_key

        self.left_file_paths = []
        self.right_file_paths = []

        self.file_status_1 = QTextEdit()
        self.file_status_1.setPlaceholderText("원본 파일을 드래그 하세요 (입력)")
        self.file_status_1.setReadOnly(True)

        self.file_status_2 = QTextEdit()
        self.file_status_2.setPlaceholderText("결과 파일이 여기에 출력됩니다 (출력)")
        self.file_status_2.setReadOnly(True)

        self.key_input = QLineEdit(self.aes_key)
        self.key_input.setReadOnly(True)
        self.key_input.setFixedWidth(200)

        self.key_label = QLabel("🔑 Key:")
        key_layout = QHBoxLayout()
        key_layout.addWidget(self.key_label)
        key_layout.addWidget(self.key_input)
        key_layout.addStretch()

        self.encrypt_btn = QPushButton("암호화")
        self.decrypt_btn = QPushButton("복호화")

        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.encrypt_btn)
        btn_layout.addWidget(self.decrypt_btn)

        self.encrypt_btn.clicked.connect(self.encrypt_files)
        self.decrypt_btn.clicked.connect(self.decrypt_files)

        layout = QVBoxLayout()
        layout.addWidget(self.file_status_1)
        layout.addWidget(self.file_status_2)
        layout.addLayout(key_layout)
        layout.addLayout(btn_layout)

        self.setLayout(layout)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        self.left_file_paths.clear()
        self.file_status_1.clear()
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            self.left_file_paths.append(path)
            self.file_status_1.append(path)

    def encrypt_files(self):
        self.right_file_paths.clear()
        self.file_status_2.clear()
        key = self.key_input.text()

        #.Henc확장자 검사. 이중암호화시 버그가 발생하므로 방지
        for path in self.left_file_paths:
            if path.endswith(".Henc"):
                QMessageBox.warning(self, "복호화 불가", ".Henc 파일은 암호화 대상이 될 수 없습니다.")
                return
        
        for path in self.left_file_paths:
            result_list = enc_aes([path], key)
            if result_list:
                result = result_list[0]
            if result:
                self.right_file_paths.append(result)
                self.file_status_2.append(result)
        self.left_file_paths.clear()
        self.file_status_1.clear()

    def decrypt_files(self):
        self.right_file_paths.clear()
        self.file_status_2.clear()
        key = self.key_input.text()
        
        for path in self.left_file_paths:
            if not isValidDec(path+".hash", key):
                QMessageBox.warning(self, "무결성 오류", f"복호화 실패: 무결성 검사 불통과\n{path}")
                continue
            result_list = dec_aes([path], key)
            if result_list:
                result = result_list[0]
            if result:
                self.right_file_paths.append(result)
                self.file_status_2.append(result)
        self.left_file_paths.clear()
        self.file_status_1.clear()
