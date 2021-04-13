from typing import Tuple, Union

import yaml

class Process:
    def __init__(self) -> None:
        self.file_path = "./data/users.yml"
        self.data = []
        self.read_collection()

    def read_collection(self):
        with open(self.file_path, "r") as stream:
            data = yaml.safe_load(stream)
            if data is None:
                data = []
            self.data = data

    def write_collection(self):
        with open(self.file_path, "w") as stream:
            yaml.dump(self.data, stream)

    def user_auth(self, ip: str, password: str) -> Tuple[int, Union[str, None]]:
        for user in self.data:
            if user["ip_addr"] == ip and user["password"] == password:
                return 1, user["username"]
        for user in self.data:
            if user["ip_addr"] == ip:
                return 0, None

        return -1, None

    def user_reg(self, ip: str, password: str, username: str) -> None:
        self.data.append({"ip_addr": ip, "password": password, "username": username})
        self.write_collection()

    def clear(self):
        self.data = []
        self.write_collection()