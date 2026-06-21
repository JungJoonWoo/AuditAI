import requests
def handler(url):
    return requests.get(url).text  # CWE-918 TP
