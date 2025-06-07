
import sys
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
from pathlib import Path
import os

class LoginWidget(QWidget):
    def __init__(self, switch_callback):
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
        id = self.id_input.text()
        pw = self.pw_input.text()

        if not id or not pw:
            QMessageBox.warning(self, "입력 오류", "ID와 비밀번호를 입력하세요.")
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(("hsu.usbenc-project.p-e.kr", 5000))
                s.sendall(f"register,{id},{pw}".encode())
                response = s.recv(1024).decode().strip()
                print(f"서버 응답 확인: [{response}]")
                if response.startswith("TOTP:"):
                    totp_key = response.split(":")[1].split("|")[0]
                    self.show_qr_popup(totp_key)
                else:
                    QMessageBox.warning(self, "오류", response)
        except Exception as e:
            QMessageBox.critical(self, "네트워크 오류", str(e))

    def login(self):
        id = self.id_input.text()
        pw = self.pw_input.text()
        otp = self.totp_input.text()

        if not id or not pw or not otp:
            QMessageBox.warning(self, "입력 오류", "ID, 비밀번호, OTP를 모두 입력하세요.")
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(("hsu.usbenc-project.p-e.kr", 5000))
                s.sendall(f"login,{id},{pw},{otp}".encode())
                response = s.recv(1024).decode().strip()
                print(f"서버 응답 확인: [{response}]")
                if response.startswith("success:"):
                    aes_key = response.split(":")[1]
                    QMessageBox.information(self, "로그인 성공", "인증에 성공했습니다.")
                    self.switch_callback(aes_key)
                else:
                    QMessageBox.warning(self, "로그인 실패", response)
        except Exception as e:
            QMessageBox.critical(self, "네트워크 오류", str(e))

    def show_qr_popup(self, totp_key):
        popup = QDialog(self)
        popup.setWindowTitle("TOTP 키 및 QR코드")
        popup.resize(300, 400)
        layout = QVBoxLayout()

        # 안전한 경로에 QR코드 저장 (Documents 하위)
        qr_dir = Path.home() / "Documents" / "USBProjectQR"
        qr_dir.mkdir(parents=True, exist_ok=True)

        qr_path = qr_dir / "totp_qr.png"
        if qr_path.exists():
            qr_path.unlink()

        # QR 생성 및 저장
        totp = pyotp.TOTP(totp_key)
        uri = totp.provisioning_uri(name=self.id_input.text(), issuer_name="USBProject")
        qr = pyqrcode.create(uri)
        qr.png(str(qr_path), scale=6)

        qr_img = QLabel()
        qr_pixmap = QPixmap(str(qr_path))
        qr_img.setPixmap(qr_pixmap)
        qr_img.setAlignment(Qt.AlignCenter)

        totp_text = QTextEdit()
        totp_text.setText(totp_key)
        totp_text.setReadOnly(True)

        copy_btn = QPushButton("TOTP 복사")
        copy_btn.clicked.connect(lambda: clipboard.copy(totp_key))

        layout.addWidget(qr_img)
        layout.addWidget(QLabel("TOTP 키:"))
        layout.addWidget(totp_text)
        layout.addWidget(copy_btn)

        button_box = QDialogButtonBox(QDialogButtonBox.Ok)
        button_box.accepted.connect(popup.accept)
        layout.addWidget(button_box)

        popup.setLayout(layout)
        popup.exec_()

class MainWindow(QStackedWidget):
    def __init__(self):
        super().__init__()
        self.login_widget = LoginWidget(self.show_encrypt_screen)
        self.addWidget(self.login_widget)
        self.setCurrentIndex(0)

    def show_encrypt_screen(self, aes_key):
        self.encrypt_widget = EncryptWidget(aes_key)
        self.addWidget(self.encrypt_widget)
        self.setCurrentIndex(1)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.setWindowTitle("AES 클라이언트")
    window.resize(600, 400)
    window.show()
    sys.exit(app.exec_())
