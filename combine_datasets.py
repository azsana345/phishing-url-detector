import pandas as pd

# Load phishing URLs (already labeled as 'label' = 1)
phish_df = pd.read_csv("openphish_dataset.csv")

# Load legit + sample URLs (with column 'is_phishing')
legit_df = pd.read_csv("url_dataset.csv")

# Rename 'is_phishing' to 'label' for consistency
legit_df.rename(columns={"is_phishing": "label"}, inplace=True)

# Combine datasets
combined_df = pd.concat([phish_df, legit_df], ignore_index=True)

# Shuffle rows for randomness
combined_df = combined_df.sample(frac=1).reset_index(drop=True)

# Save to new CSV file
combined_df.to_csv("combined_dataset.csv", index=False)

print(f"[OK] Combined dataset saved as 'combined_dataset.csv' with {len(combined_df)} rows.")
