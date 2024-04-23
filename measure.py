import requests
import csv
from urllib.parse import urlparse

# List of websites to crawl
websites = [
    "https://www.google.com",
    "https://mail.google.com",
    "https://www.amazon.com",
    "https://aws.amazon.com",
    "https://www.github.com",
    "https://gist.github.com",
    "https://www.wikipedia.org",
    "https://en.wikipedia.org",
    "https://www.stackoverflow.com",
    "https://meta.stackoverflow.com",
    "https://www.microsoft.com",
    "https://outlook.live.com",
    "https://www.apple.com",
    "https://developer.apple.com",
    "https://www.netflix.com",
    "https://media.netflix.com",
    "https://www.paypal.com",
    "https://developer.paypal.com",
    "https://www.nytimes.com",
    "https://cooking.nytimes.com",
    "https://www.bbc.co.uk",
    "https://www.bbc.com/news",
    "https://www.reddit.com",
    "https://old.reddit.com",
]

# Output file setup
output_file = 'hsts_policies.csv'
with open(output_file, mode='w', newline='', encoding='utf-8') as file:
    writer = csv.writer(file)
    writer.writerow(["Domain", "HSTS Policy"])

    for website in websites:
        try:
            response = requests.get(website, timeout=5)
            hsts_policy = response.headers.get('Strict-Transport-Security', 'Not Found')

            # Extracts domain name for readability
            domain = urlparse(website).netloc

            # Write the domain and its HSTS policy to the CSV file
            writer.writerow([domain, hsts_policy])

        except requests.RequestException as e:
            print(f"Request failed for {website}: {e}")

print(f"HSTS policies collected and stored in {output_file}")
