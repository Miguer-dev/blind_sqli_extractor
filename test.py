import requests

response = requests.get("http://192.168.1.103")
print(response.text)
