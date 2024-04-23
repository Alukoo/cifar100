import csv


# Function to extract max-age value from the HSTS policy
def extract_max_age(policy):
    try:
        # Finds the max-age directive and extract its value
        max_age_str = [part for part in policy.split(';') if 'max-age' in part][0]
        max_age_value = int(max_age_str.split('=')[1])
        return max_age_value
    except (IndexError, ValueError):
        # Returns None if max-age is not found or if there's an error parsing it
        return None

# Enhanced function to classify the security level based on HSTS policy, with case-insensitive checks
def classify_security(policy):
    policy_lower = policy.lower()  # Converts the policy to lowercase for case-insensitive comparison
    if "not found" in policy_lower or "max-age" not in policy_lower:
        return "No HSTS Policy"
    if "max-age=0" in policy_lower:
        return "Disabled"

    max_age = extract_max_age(policy)
    if max_age is None:
        return "Malformed Policy"

    # Categorizes based on max-age value, considering a more granular approach
    if max_age < 1800:  # Less than 30 minutes
        security_level = "Very Low"
    elif max_age < 86400:  # Less than 1 day
        security_level = "Low"
    else:
        security_level = "Basic"

    if "includesubdomains" in policy_lower:
        security_level = "Intermediate"
    if "preload" in policy_lower:
        security_level = "High"

    return security_level



# Reads the HSTS policies from the CSV file
input_file = 'hsts_policies.csv'
with open(input_file, mode='r', encoding='utf-8') as file:
    reader = csv.DictReader(file)

    # For each row in the CSV, print the domain, HSTS policy, and classified security level
    for row in reader:
        domain = row["Domain"]
        hsts_policy = row["HSTS Policy"]
        security_level = classify_security(hsts_policy)
        print(f"Domain: {domain}, HSTS Policy: {hsts_policy}, Security Level: {security_level}")
