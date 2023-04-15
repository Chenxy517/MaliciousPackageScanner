import requests

# Replace with your own email address
email = "account-exists@hibp-integration-tests.com"

# API endpoint URL with the email address as a parameter
url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"

# Set the headers with your API key (optional)
headers = {
    "hibp-api-key": "b36f62e394e948a78667521d9621a82a"
}

# Send the GET request to the API
response = requests.get(url, headers=headers)

# Check the response status code
if response.status_code == 200:
    # The email address has been compromised, print the details of the data breaches
    print("Your email address has been compromised in the following data breaches:")
    for breach in response.json():
        print(breach["Name"])
else:
    # The email address has not been compromised or there was an error, print the response status code and reason
    print(f"Request failed with status code {response.status_code}: {response.reason}")
