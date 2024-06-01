import argparse
import time
import random
from requests.exceptions import HTTPError
import requests
from tqdm import tqdm
from shodan import Shodan
from shodan.cli.helpers import get_api_key
import re

OUTPUT_FILE = 'recon.txt'
FILTERED_FILE = 'filtered.txt'
GOOGLE_API_KEY = # Your Google API key
CSE_ID = # Your CSE_ID
SHODAN_API_KEY = Shodan(get_api_key())
GITHUB_PAT = # Your GitHub PAT

def perform_dorking(queries):
    results = {}
    with open(OUTPUT_FILE, 'a') as f:
        f.write("### GOOGLE DORKING ###\n")
    for query in tqdm(queries, desc="Performing Google Dorking"):
        search_results = google_search(query)
        results[query] = search_results
        try:
            with open(OUTPUT_FILE, 'a') as f:
                f.write(f"[*] Results for {query}:\n")
                for result in search_results:
                    f.write(result + "\n")
        except Exception as e:
            print(f"[!] Exception: {e}")
        time.sleep(random.uniform(10, 20))  # Random delay between 10 and 20 seconds
    return results

def google_search(query):
    search_results = []
    url = f"https://www.googleapis.com/customsearch/v1?q={query}&key={GOOGLE_API_KEY}&cx={CSE_ID}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        for item in data.get('items', []):
            search_results.append(item['link'])
    except requests.exceptions.HTTPError as err:
        print(f"[!] HTTP error occurred: {err}")
    except Exception as err:
        print(f"[!] An error occurred: {err}")
    return search_results

def perform_shodan_search(queries):
    results = {}
    with open(OUTPUT_FILE, 'a') as f:
        f.write("### SHODAN QUERIES ###\n")
    for query in tqdm(queries, desc="Performing Shodan Search"):
        search_results = shodan_search(query)
        results[query] = search_results
        try:
            with open(OUTPUT_FILE, 'a') as f:
                f.write(f"[*] Results for {query}:\n")
                for result in search_results:
                    f.write(result + "\n")
        except Exception as e:
            print(f"[!] Exception: {e}")
        time.sleep(random.uniform(10, 20))  # Random delay between 10 and 20 seconds
    return results

def shodan_search(query):
    search_results = []
    try:
        results = SHODAN_API_KEY.search(query)
        for match in results['matches']:
            search_results.append(match['ip_str'])
    except Exception as e:
        print(f"[!] An error occurred: {e}")
    return search_results

def perform_github_search(queries):
    results = {}
    headers = {'Authorization': f'token {GITHUB_PAT}'}
    with open(OUTPUT_FILE, 'a') as f:
        f.write("### GITHUB SEARCH ###\n")
    for query in tqdm(queries, desc="Performing GitHub Search"):
        search_results = github_search(query, headers)
        results[query] = search_results
        try:
            with open(OUTPUT_FILE, 'a') as f:
                f.write(f"[*] Results for {query}:\n")
                for result in search_results:
                    f.write(result + "\n")
        except Exception as e:
            print(f"[!] Exception: {e}")
        time.sleep(random.uniform(10, 20))  # Random delay between 10 and 20 seconds
    return results

def github_search(query, headers):
    search_results = []
    url = f"https://api.github.com/search/code?q={query}"
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        for item in data.get('items', []):
            search_results.append(item['html_url'])
    except requests.exceptions.HTTPError as err:
        print(f"[!] HTTP error occurred: {err}")
    except Exception as err:
        print(f"[!] An error occurred: {err}")
    return search_results

def check_directories(directories):
        header = {'X-HackerOne-Research': '[Flawedspoon]'}
        results = {}
        with open(OUTPUT_FILE, 'a') as f:
            f.write("### DIRECTORY CHECK ###\n")
            for directory in tqdm(directories, desc="Checking directories"):
                url = directory
                try:
                    response = requests.get(url, headers=header)
                    f.write(f"{url}: {response.status_code}\n")
                    if response.status_code == 200:
                        if url == f"https://{TARGET}/robots.txt":
                            response.raise_for_status()
                            data = response.text  # Read the text content of the robots.txt file
                            search_results = data.splitlines()  # Split the content by lines
                            f.write(f"[*] Robots.txt contents for {TARGET}:\n")
                            for line in search_results:
                                f.write(line + "\n")
                        results[directory] = url
                except requests.exceptions.RequestException as e:
                    print(f"[!] Error checking {url}: {e}")
                time.sleep(random.uniform(10, 20))  # Random delay between 10 and 20 seconds
        return results

def search_wayback_machine(directories):
    with open(OUTPUT_FILE, 'a') as f:
        f.write("### WAYBACK MACHINE RESULTS ###\n")
        url = "http://web.archive.org/cdx/search/cdx"
        for uri in tqdm(directories, desc="Searching the Wayback Machine"):
            params = {
                'url': uri,
                'output': 'json',
                'fl': 'timestamp,original,mimetype,statuscode,digest,length',
                'filter': 'statuscode:200',
                'limit': 10,
                'collapse': 'digest'
            }

            try:
                response = requests.get(url, params=params)
                response.raise_for_status()
                data = response.json()

                if len(data) > 1:  # Check if there are any results
                    for entry in data[1:]:
                        timestamp, original, mimetype, statuscode, digest, length = entry
                        archive_url = f"http://web.archive.org/web/{timestamp}/{original}"
                        f.write(f"{archive_url}\n")
                else:
                    f.write(f"[*] No results found for {uri}\n")

            except requests.exceptions.RequestException as e:
                print(f"[!] Error searching {uri}: {e}")
                f.write(f"[!] Error searching {uri}: {e}\n")

            time.sleep(random.uniform(10, 20))  # Random delay between 10 and 20 seconds

def filter_results(target):
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    with open(OUTPUT_FILE, 'r') as infile, open(FILTERED_FILE, 'a') as outfile:
        for line in tqdm(infile, desc="Filtering results"):
            if (line.startswith('#') or (target in line and not line.startswith(('[!]', '[*]', '[+]', '[x]'))) or ip_pattern.search(line)):
                outfile.write(line)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Performing automated recon for bug bounty hunting')
    parser.add_argument('-t', help='Target URL', required=True)
    args = parser.parse_args()

    TARGET = args.t

    directories = [
        f"https://{TARGET}/admin/",
        f"https://{TARGET}/login/",
        f"https://{TARGET}/backup/",
        f"https://{TARGET}/config/",
        f"https://{TARGET}/uploads/",
        f"https://{TARGET}/files/",
        f"https://{TARGET}/temp/",
        f"https://{TARGET}/old/",
        f"https://{TARGET}/test/",
        f"https://{TARGET}/dev/",
        f"https://{TARGET}/staging/",
        f"https://{TARGET}/scripts/",
        f"https://{TARGET}/db/",
        f"https://{TARGET}/includes/",
        f"https://{TARGET}/cgi-bin/",
        f"https://{TARGET}/private/",
        f"https://{TARGET}/data/",
        f"https://{TARGET}/logs/",
        f"https://{TARGET}/secrets/",
        f"https://{TARGET}/source/",
        f"https://{TARGET}/docs/",
        f"https://{TARGET}/api/docs/",
        f"https://docs.{TARGET}/",
        f"https://dev.{TARGET}/docs/",
        f"https://developer.{TARGET}/docs/",
        f"https://api.{TARGET}/docs/",
        f"https://api.{TARGET}/",
        f"https://{TARGET}/developers/documentation/",
        f"https://{TARGET}/robots.txt"
    ]

    dorking_queries = [
        f"site: {TARGET} inurl: /wp-json/wp/v2/users",
        f"site: {TARGET} intitle: index.of intext: api.txt",
        f"site: {TARGET} ext: php inurl: api.php?action=",
        f"site: {TARGET} intitle: index of api_key OR api key OR apiKey -pool",
        f"site: {TARGET} intitle: index of graphql-api",
        f"site: {TARGET} _API_KEY=sk-",
        f"site: {TARGET} intitle: index of /api/",
        f"site: {TARGET} intitle: Sharing API Info",
        f"site: {TARGET} inurl: /api-docs"
    ]

    shodan_queries = [
        f"hostname:www.{TARGET} content-type:application/json",
        f"hostname:www.{TARGET} content-type:application/xml",
        f"hostname:www.{TARGET} 200 OK",
        f"hostname:www.{TARGET} wp-json"
    ]

    github_queries = [
        f"{TARGET} wp-json",
        f"{TARGET} api_key",
        f"{TARGET} api-key",
        f"{TARGET} secrets",
        f"{TARGET} password",
        f"{TARGET} token"
    ]

    # Perform Google Search
    print(f"[*] Performing Google search for {TARGET}.")
    google_results = perform_dorking(dorking_queries)

    # Perform Shodan Search
    print(f"[*] Performing Shodan search for {TARGET}.")
    shodan_results = perform_shodan_search(shodan_queries)

    # Perform GitHub Search
    print(f"[*] Performing GitHub search for {TARGET}.")
    github_results = perform_github_search(github_queries)

    # Perform quick directory check
    print(f"[*] Performing directory search for {TARGET}.")
    directory_results = check_directories(directories)

    # Perform Wayback Machine search
    print(f"[*] Performing Wayback Machine search for {TARGET}.")
    search_wayback_machine(directories)

    # Filter results
    print(f"[*] Filtering results for {TARGET}.")
    filter_results(TARGET)

    # FIN #
    print("Done.")
