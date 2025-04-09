
import csv
from heuristics import check_phishing
from ml_model import predict_url


def main():
    try:
        with open("urls.txt", "r") as file:
            urls = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print("The file 'urls.txt' was not found.")
        return

    print("🔍 Phishing URL Detection Results:\n")

    # Prepare to write CSV output
    with open("results.csv", mode="w", newline="") as csv_file:
        fieldnames = [
    "URL", "Domain", "Has IP", "Suspicious Keywords", 
    "Long URL", "Contains @", "Phishing Score (%)", "Is Phishing"
        ]

        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        for url in urls:
            result = check_phishing(url)
            
            # Print to console
            print(f"URL: {url}")
            print(f"  Domain: {result['domain']}")
            print(f"  ⚠️ Has IP address: {result['has_ip_address']}")
            print(f"  ⚠️ Suspicious keywords: {result['has_suspicious_words']}")
            print(f"  ⚠️ Long URL: {result['is_long_url']}")
            print(f"  ⚠️ Contains '@': {result['has_at_symbol']}")
            print(f"  🧮 Phishing Score: {result['phishing_score']}%")
            print(f"  🔴 Heuristic Result: {result['is_phishing']}")
            ml_prediction = predict_url(url)
            print(f"  🤖 ML Prediction: {ml_prediction} ({'Phishing' if ml_prediction == 1 else 'Legit'})")
            print("-" * 60)

            # Write to CSV
            writer.writerow({
    "URL": url,
    "Domain": result["domain"],
    "Has IP": result["has_ip_address"],
    "Suspicious Keywords": result["has_suspicious_words"],
    "Long URL": result["is_long_url"],
    "Contains @": result["has_at_symbol"],
    "Phishing Score (%)": result["phishing_score"],
    "Is Phishing": result["is_phishing"]
})


if __name__ == "__main__":
    main()
