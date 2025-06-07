? wsl필수 설치 명령어

sudo apt update
sudo apt install mysql-server
sudo service mysql start

server
pip install pyotp
pip install pyqrcode pypng
pip install pyotp pyqrcode pypng
pip install mysql-connector-python

client
pip install --upgrade Pillow
pip install PyQt5 requests
pip install pyqrcode pypng clipboard
pip install qrcode

----------------------------------------------------------------------------------
? server.py에서 접속하기 위해 비밀번호설정

mysql -u root -p

ALTER USER 'root'@'%' IDENTIFIED BY '1234'

FLUSH PRIVILEGES;

? DB + table 생성

CREATE DATABASE usb_project;

USE usb_project; --DB선택

CREATE TABLE users (

    id VARCHAR(50) PRIMARY KEY,
    
    pw VARCHAR(100) NOT NULL,
    
    totp VARCHAR(100) NOT NULL,
    
    aes_key CHAR(16) NOT NULL
    
);

? DB확인
USE usb_project; --DB선택
SHOW TABLES;
DESC users;
SHOW COLUMNS FROM users;
SELECT * FROM users;
SELECT COUNT(*) FROM users;


----------------------------------------------------------------------------------
? 윈도우와 WSL IP연결

ps > netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=5000 connectaddress=MY_WSL_IP connectport=5000
? 내 WSL 주소 탐색방법

wsl에서 다음과 같은 명령어 실행
wsl > ip addr show eth0
> inet 192.168.168.195/20 brd 192.168.175.255 scope global eth0
이 경우 내 WSL주소는 "192.168.168.195"이다.
ex)
> ps > netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=5000 connectaddress=192.168.168.195 connectport=5000
