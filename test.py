#!/usr/bin/python3

import requests

headers = {"Cookie": "PHPSESSID=tjqhdl7m9qjkvu1nbvkv29pm86"}
response = requests.get(
    "http://192.168.1.103/imfadministrator/cms.php?pagename=home", headers=headers
)
print(response.text)
