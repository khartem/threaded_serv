import json
from json.decoder import JSONDecodeError
import logging
import random
import socket
import threading
import os
import sys
from typing import Dict, Union, Any
from process import Process

currentdir = os.path.dirname(os.path.realpath(__file__))
parentdir = os.path.dirname(currentdir)
sys.path.append(parentdir)
from validator import port_validation, check_port_open

END_MESSAGE_FLAG = "CRLF"
DEFAULT_PORT = 9090
LOGGER_FILE = "./logs/server.log"
# Настройки логирования
logging.basicConfig(
    format="%(asctime)-15s [%(levelname)s] %(funcName)s: %(message)s",
    handlers=[logging.FileHandler(LOGGER_FILE)],
    level=logging.INFO,
)
logger = logging.getLogger(__name__)
stream_handler = logging.StreamHandler()
stream_handler.setLevel(logging.INFO)
logger.addHandler(stream_handler)

class Server:
    def __init__(self, port_number: int) -> None:

        logger.info(f"Запуск сервера")
        self.port_number = port_number
        self.sock = None
        self.database = DataProcessing()
        self.socket_init()
        self.authenticated_list = []
        self.reg_list = []
        self.connections_list = []
        self.ip2username_dict = {}
        logger.info(f"Сервер инициализировался, слушает порт {port_number}")
        self.connection_thread = None
        self.play_command()
        self.input_processing()

    def connection_processing(self):
        while self.receive_data:
            conn, addr = self.sock.accept()
            self.connections_list.append((conn, addr))
            logger.info(f"Новое соединение от {addr[0]}")
            t = threading.Thread(target=self.router, args=(conn, addr))
            t.daemon = True
            t.start()

    def exit_command(self):
        logger.info("Завершаем работу сервера")
        sys.exit()

    def stop_command(self):
        self.receive_data = False
        logger.info("Приостановилен поток получения данных клиентов")

    def clear_auth_command(self):
        self.database.clear()
        logger.info("Отчищен файл авторизации пользователей")

    def start_logs_command(self):
        if stream_handler not in logger.handlers:
            logger.addHandler(stream_handler)
            logger.info("Возобновлен показ логов в консоли")

    def stop_logs_command(self):
        if stream_handler in logger.handlers:
            logger.removeHandler(stream_handler)
            logger.info("Приостановлен показ логов в консоли")

    def clear_logs_command(self):
        open(LOGGER_FILE, "w").close()
        logger.info("Отчищен файл логов")

    def play_command(self):
        self.receive_data = True
        t = threading.Thread(target=self.connection_processing)
        t.daemon = True
        t.start()
        self.connection_thread = t

    def send_message(self, conn, data: Union[str, Dict[str, Any]], ip: str) -> None:
        data_text = data
        if type(data) == dict:
            data = json.dumps(data, ensure_ascii=False)

        data = data.encode()
        conn.send(data)
        logger.info(f"Сообщение {data_text} было отправлено клиенту {ip}")

    def socket_init(self):
        sock = socket.socket()
        sock.bind(("", self.port_number))
        sock.listen(0)
        self.sock = sock

    def message_logic(self, conn, client_ip):
        data = ""
        while True:
            chunk = conn.recv(1024)
            data += chunk.decode()
            if END_MESSAGE_FLAG in data:

                username = self.ip2username_dict[client_ip]
                logger.info(
                    f"Получено сообщение {data} от клиента {client_ip} ({username})"
                )
                data = {"username": username, "text": data}
                logger.info(
                    f"Текущее кол-во подключений к серверу: {len(self.connections_list)}"
                )
                for connection in self.connections_list:
                    current_conn, current_ip = connection
                    try:
                        self.send_message(current_conn, data, current_ip)
                    except BrokenPipeError:
                        continue
                data = ""
            else:
                logger.info(f"Принята часть данных от клиента {client_ip}: '{data}'")
            if not chunk:
                break

    def reg_logic(self, conn, addr):
        newuser_ip = addr[0]
        try:
            data = json.loads(conn.recv(1024).decode())
        except JSONDecodeError:
            if newuser_ip in self.reg_list:
                self.reg_list.remove(newuser_ip)
            return
        newuser_password, newuser_username = hash(data["password"]), data["username"]
        self.database.user_reg(newuser_ip, newuser_password, newuser_username)
        logger.info(f"Клиент {newuser_ip} -> регистрация прошла успешно")
        data = {"result": True}
        if newuser_ip in self.reg_list:
            self.reg_list.remove(newuser_ip)
            logger.info(f"Удалили клиента {newuser_ip} из списка регистрации")
        self.send_message(conn, data, newuser_ip)
        logger.info(f"Клиент {newuser_ip}. Отправили данные о результате регистрации")

    def auth_logic(self, conn, addr):
        try:
            user_password = hash(json.loads(conn.recv(1024).decode())["password"])
        except JSONDecodeError:
            return
        client_ip = addr[0]
        auth_result, username = self.database.user_auth(client_ip, user_password)
        if auth_result == 1:
            logger.info(f"Клиент {client_ip} -> авторизация прошла успешно")
            data = {"result": True, "body": {"username": username}}
            if client_ip not in self.authenticated_list:
                self.authenticated_list.append(client_ip)
                self.ip2username_dict[client_ip] = username
                logger.info(f"Добавление клиента {client_ip} в список авторизации")
        elif auth_result == 0:
            logger.info(f"Клиент {client_ip} -> авторизация не удалась")
            data = {"result": False, "description": "wrong auth"}
        else:
            logger.info(
                f"Клиент {client_ip} -> необходима регистрация в системе"
            )
            data = {"result": False, "description": "registration required"}
            if client_ip not in self.reg_list:
                self.reg_list.append(client_ip)
                logger.info(f"Добавление клиента {client_ip} в список регистрации")
        self.send_message(conn, data, client_ip)
        logger.info(f"Клиент {client_ip}. Отправлены данные о результате авторизации")
        if auth_result == 1:
            self.message_logic(conn, client_ip)

    def router(self, conn, addr):
        logger.info("Router работает в отдельном потоке!")
        client_ip = addr[0]
        if client_ip in self.reg_list:
            self.reg_logic(conn, addr)
        elif client_ip not in self.authenticated_list:
            self.auth_logic(conn, addr)
        else:
            self.message_logic(conn, client_ip)
        logger.info(f"Отключение клиента {client_ip}")
        self.connections_list.remove((conn, addr))
        if client_ip in self.authenticated_list:
            self.authenticated_list.remove(client_ip)
            print("Список соединений:")
            print(self.connections_list)
            logger.info(f"Удалили клиента {client_ip} из списка авторизации")

    def __del__(self):
        logger.info(f"Остановка сервера")


def main():
    port_input = input("Введите номер порта для сервера: ")
    port_flag = port_validation(port_input, check_open=True)
    if not port_flag:
        if not check_port_open(DEFAULT_PORT):
            print(
                f"Порт по умолчанию {DEFAULT_PORT} уже занят! Подбирка рандомного порта"
            )
            stop_flag = False
            while not stop_flag:
                current_port = random.randint(49152, 65535)
                print(f"Сгенерирован рандомный порт {current_port}")
                stop_flag = check_port_open(current_port)
            port_input = current_port
        else:
            port_input = DEFAULT_PORT
        print(f"Выставлен порт {port_input} по умолчанию")
    server = Server(int(port_input))

if __name__ == "__main__":
    main()