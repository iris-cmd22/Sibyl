import requests


def fetch(url):
    response = requests.get(url, verify=False)
    return response.text


def post_data(url, payload):
    return requests.post(url, json=payload, verify=False).status_code
