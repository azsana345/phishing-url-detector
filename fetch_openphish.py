import requests
import csv

def fetch_openphish():
    # URL to OpenPhish public feed
    feed_url = "https://openphish.com/feed.txt"

    try:
        print("[*] Downloading OpenPhish feed...")
        response = requests.get(feed_url)
        response.raise_for_status()

        urls = response.text.strip().split("\n")
        urls = list(set(urls))  # Remove duplicates

        print(f"[+] Fetched {len(urls)} phishing URLs.")

        # Save to CSV file with label = 1 (phishing)
        with open("openphish_dataset.csv", mode="w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["url", "label"])
            for url in urls:
                writer.writerow([url.strip(), 1])

        print("[OK] Saved to 'openphish_dataset.csv' successfully.")

    except Exception as e:
        print("[ERROR] Failed to fetch OpenPhish feed:", e)

if __name__ == "__main__":
    fetch_openphish()
