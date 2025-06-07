
import sys
import os
import socket
import pyqrcode
import clipboard
import pyotp
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLineEdit, QPushButton, QLabel,
    QVBoxLayout, QHBoxLayout, QMessageBox, QStackedWidget, QTextEdit,
    QDialog, QDialogButtonBox
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap
from EncryptWidget import EncryptWidget

class LoginWidget(QWidget):
    def __init__(self, switch_callback):
        #로그인 화면 초기화: ID, PW, OTP 입력 필드 및 회원가입/로그인 버튼 생성
        super().__init__()
        self.switch_callback = switch_callback

        self.id_input = QLineEdit()
        self.id_input.setPlaceholderText("ID 입력")

        self.pw_input = QLineEdit()
        self.pw_input.setPlaceholderText("Password 입력")
        self.pw_input.setEchoMode(QLineEdit.Password)

        self.totp_input = QLineEdit()
        self.totp_input.setPlaceholderText("6자리 OTP 입력")

        self.register_btn = QPushButton("회원가입")
        self.login_btn = QPushButton("로그인")

        self.register_btn.clicked.connect(self.register)
        self.login_btn.clicked.connect(self.login)

        layout = QVBoxLayout()
        layout.addWidget(QLabel("ID:"))
        layout.addWidget(self.id_input)
        layout.addWidget(QLabel("Password:"))
        layout.addWidget(self.pw_input)
        layout.addWidget(QLabel("TOTP:"))
        layout.addWidget(self.totp_input)

        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.register_btn)
        btn_layout.addWidget(self.login_btn)

        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def register(self):
        #ID,PW 서버에 회원가입 요청, TOTP 키를 받으면 QR코드 이미지,코드 팝업
        id = self.id_input.text()
        pw = self.pw_input.text()

        if not id or not pw:
            QMessageBox.warning(self, "입력 오류", "ID와 비밀번호를 입력하세요.")
            return

        try:
            # 서버에 소켓 연결
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(("127.0.0.1", 5000))
                s.sendall(f"register,{id},{pw}".encode())
                response = s.recv(1024).decode().strip()
                print(f"서버 응답 확인: [{response}]")
                if response.startswith("TOTP:"):
                    totp_key = response.split("TOTP:")[1]
                    self.show_qr_popup(totp_key)
                else:
                    QMessageBox.warning(self, "오류", response)
        except Exception as e:
            QMessageBox.critical(self, "네트워크 오류", str(e))

    def login(self):
        #ID, 비밀번호, OTP를 입력받아 서버에 로그인 요청
        id = self.id_input.text()
        pw = self.pw_input.text()
        otp = self.totp_input.text()

        if not id or not pw or not otp:
            QMessageBox.warning(self, "입력 오류", "ID, 비밀번호, OTP를 모두 입력하세요.")
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(("127.0.0.1", 5000))
                s.sendall(f"login,{id},{pw},{otp}".encode())
                response = s.recv(1024).decode()
                if "success" in response.lower():
                    QMessageBox.information(self, "로그인 성공", "인증에 성공했습니다.")
                    self.switch_callback()
                else:
                    QMessageBox.warning(self, "로그인 실패", response)
        except Exception as e:
            QMessageBox.critical(self, "네트워크 오류", str(e))

    def show_qr_popup(self, totp_key):
        #TOTP 키와 QR코드를 새 창(QDialog)에 표시하고, 복사 버튼과 확인 버튼을 제공

        # 팝업 창을 QDialog로 생성
        popup = QDialog(self)
        popup.setWindowTitle("TOTP 키 및 QR코드")
        popup.resize(300, 400)
        layout = QVBoxLayout()

        # 전달받은 TOTP 키로 QR 코드 생성
        totp = pyotp.TOTP(totp_key)
        uri = totp.provisioning_uri(name=self.id_input.text(), issuer_name="USBProject")
        qr = pyqrcode.create(uri)
        # QR코드를 이미지 파일로 저장 (.png 파일 생성)
        qr.png("totp_qr.png", scale=6)
        # QLabel에 QR코드 이미지 로드
        qr_img = QLabel()
        qr_pixmap = QPixmap("totp_qr.png")
        qr_img.setPixmap(qr_pixmap)
        qr_img.setAlignment(Qt.AlignCenter)
        # TOTP 키를 텍스트 형태로 보여주는 텍스트 창 생성
        totp_text = QTextEdit()
        totp_text.setText(totp_key) # totp 키 텍스트 설정
        totp_text.setReadOnly(True) # 수정 불가로 설정

        # 복사 버튼 생성 (클립보드 복사 기능 연결)
        copy_btn = QPushButton("TOTP 복사")
        copy_btn.clicked.connect(lambda: clipboard.copy(totp_key)) # 클릭 시 키를 클립보드에 복사

        # QR 이미지, 키 표시, 복사 버튼을 레이아웃에 추가
        layout.addWidget(qr_img)
        layout.addWidget(QLabel("TOTP 키:"))
        layout.addWidget(totp_text)
        layout.addWidget(copy_btn)

        # 확인 버튼
        button_box = QDialogButtonBox(QDialogButtonBox.Ok)
        button_box.accepted.connect(popup.accept)
        layout.addWidget(button_box)

        # 최종 레이아웃 설정 및 창 표시
        popup.setLayout(layout)
        popup.exec_()

# class EncryptWidget(QWidget):
#     def __init__(self):
#         """암호화 화면 초기 텍스트 표시"""
#         super().__init__()
#         label = QLabel("여기는 파일 암호화/복호화 화면입니다.")
#         layout = QVBoxLayout()
#         layout.addWidget(label)
#         self.setLayout(layout)

class MainWindow(QStackedWidget):
    def __init__(self):
        """앱 실행 시 로그인 화면과 암호화 화면을 스택으로 관리"""
        super().__init__()
        self.login_widget = LoginWidget(self.show_encrypt_screen)
        self.encrypt_widget = EncryptWidget()

        self.addWidget(self.login_widget)
        self.addWidget(self.encrypt_widget)
        self.setCurrentIndex(0)

    def show_encrypt_screen(self):
        """로그인 성공 시 암호화 화면으로 전환"""
        self.setCurrentIndex(1)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.setWindowTitle("AES 클라이언트")
    window.resize(400, 400)
    window.show()
    sys.exit(app.exec_())
