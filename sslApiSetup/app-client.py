import requests
import time



# Disable SSL certificate verification (only for testing with self-signed certificates)
# Remove this line in production or use a valid SSL certificate
requests.packages.urllib3.disable_warnings()
cert_file_path='client.crt'
key_file_path='client.key'
cert=(cert_file_path, key_file_path)
url = 'https://example.com:5000/?user=kalai'
dbcall = 'https://example.com:5000/db'


while True:
    # Make the GET request
    response = requests.get(url, verify=False)

    # Check the response status code
    if response.status_code == 200:
        # Print the response content
        print(response.text)
    else:
        print('Request failed with status code:', response.status_code)
    time.sleep(2)
        # Make the GET request
    response = requests.get(dbcall, verify=True)

    # Check the response status code
    if response.status_code == 200:
        # Print the response content
        print(response.text)
    else:
        print('Request failed with status code:', response.status_code)
    time.sleep(2)