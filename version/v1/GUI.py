import sys
import os
from PyQt5.QtWidgets import (
    QApplication, QWidget, QTextEdit, QLineEdit,
    QPushButton, QHBoxLayout, QVBoxLayout
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QDropEvent, QDragEnterEvent

#AES.py
from AES import enc_aes
from AES import dec_aes

class AESGui(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AES 암호화/복호화 UI")
        self.resize(800, 600)
        self.setAcceptDrops(True)

        # ✅ 드롭된 파일 저장용 리스트
        self.left_file_paths = []
        self.right_file_paths = []

        # ✅ UI 구성
        self.file_status_1 = QTextEdit()
        self.file_status_1.setPlaceholderText("왼쪽에 파일을 드래그 하세요")
        self.file_status_1.setReadOnly(True)

        self.file_status_2 = QTextEdit()
        self.file_status_2.setPlaceholderText("오른쪽에 파일을 드래그 하세요")
        self.file_status_2.setReadOnly(True)

        self.key_input = QLineEdit("a1c3e9f207b64d58")
        self.key_input.setPlaceholderText("KEY 값을 입력하세요")

        self.encrypt_btn = QPushButton("암호화")
        self.decrypt_btn = QPushButton("복호화")
        
        # ✅ 버튼 기능 연결
        self.encrypt_btn.clicked.connect(self.run_encrypt)
        self.decrypt_btn.clicked.connect(self.run_decrypt)

        # ✅ 레이아웃
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



    #드래그 드랍기능
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        # event.mimeData() : 드래그 중인 데이터에 대한 정보 객체를 반환
        # .hasUrls() : 드래그된 데이터가 파일 또는 URL인지 확인
        # event.acceptProposedAction() : 드래그가 유효하다고 판단하고, 드롭을 허용함

    def dropEvent(self, event: QDropEvent):
        paths = [url.toLocalFile() for url in event.mimeData().urls()]
        # event.mimeData().urls() : 드랍된 파일들 경로 목록
        x_pos = event.pos().x()
        # event.pos().x() : 드롭된 위치 x좌표 -> 기준으로 좌/우 드랍 판단
        mid = self.width() // 2

        if x_pos < mid:
            self.left_file_paths = paths
            self.file_status_1.setText("왼쪽 드롭된 파일:\n" + "\n".join(paths))
        else:
            self.right_file_paths = paths
            self.file_status_2.setText("오른쪽 드롭된 파일:\n" + "\n".join(paths))

    #암호화 기능
    def run_encrypt(self):
        key = self.key_input.text() #key입력받아오기
        if len(self.left_file_paths) == 0:
            print("왼쪽에 파일을 먼저 드래그하세요.")
            return
        if not key:
            print("KEY 값을 입력하세요.")
            return

        # 1. 암호화
        self.right_file_paths = enc_aes(self.left_file_paths, key)

        # 2. 왼쪽 창 비우기
        self.left_file_paths = []
        self.file_status_1.clear()

        # 3. 오른쪽 창에 암호화된 파일 목록 출력
        self.file_status_2.setText("암호화된 파일:\n" + "\n".join(self.right_file_paths))
    
    #복호화 기능
    def run_decrypt(self):
        key = self.key_input.text() #key입력받아오기
        if len(self.right_file_paths) == 0:
            print("오른쪽에 암호화된 파일을 먼저 드래그하세요.")
            return
        if not key:
            print("KEY 값을 입력하세요.")
            return

        # 1. 복호화
        self.left_file_paths = dec_aes(self.right_file_paths, key)

        # 2. 오른쪽 창 비우기
        self.right_file_paths = []
        self.file_status_2.clear()
        
        # 3. 왼쪽 창에 암호화된 파일 목록 출력
        self.file_status_1.setText("복호화된 파일:\n" + "\n".join(self.left_file_paths))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AESGui()
    window.show()
    sys.exit(app.exec_())