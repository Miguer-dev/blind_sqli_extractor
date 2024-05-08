# Blind SQLi Extractor
This tool was created in order to automate the exploitation of blind SQL injections while I was practicing my scripting with python.
## Usage
You need to modify the main.py file to add the injection parameters.
![image](https://github.com/Miguer-dev/blind_sqli_extractor/assets/84145027/a0dacc2c-80c6-46b0-a7cb-d9823e93306b)
- `main_url`: url of the website, specifically where the exploit is located. It must contain **http://** or **https://**.
- `headers`: map with the headers of the request. Include cookies.
- `method`:
    - `PostRequest()` 
    - `GetRequest()` 
- `data`: in case of a Post type request, add a map with the data to be sent. In case of GET, add a string with the value passed by url.
- `atribute_to_exploit`: only add in case of Post, name of the field in data where to add the payload.
- `condition`: condition that must be met for the request to be True.
    - `TextInCondition()`: a specific text is found in the response.
    - `StatusEqualCondition()`: response status.
- `payload`: only one for now `ConditionalPayload()`.
- `num_threads`: number of threads to use to make several requests without waiting for responses.
