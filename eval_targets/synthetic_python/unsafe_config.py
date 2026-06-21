import requests
def f(u): return requests.get(u, verify=False)  # insecure config
DEBUG = True  # insecure config
