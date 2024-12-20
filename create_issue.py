import os
import json
import requests
import sys

def parse_severities(argv):
    """
    Parse and validate severity levels from the command-line arguments.

    Args:
        argv (list): A list of command-line arguments, where argv[1] should contain 
                     a comma-separated string of severities (e.g. "critical,high,medium").

    Returns:
        dict or None: A dictionary keyed by the valid chosen severities, each associated 
                      with an empty list, or None if no valid severities are provided.
    """
    # Check for severity argument
    if len(argv) < 2:
        print("Usage: python create_issue.py <severities>")
        print("Example: python create_issue.py critical,high,medium")
        return None

    # Parse and normalize severity levels
    severities = argv[1].split(',')
    severities = [s.strip().lower() for s in severities]  # Ensure lowercase and strip spaces
    valid_severities = {'low', 'medium', 'high', 'critical'}

    # Filter out invalid severities
    chosen_severities = [s for s in severities if s in valid_severities]

    if not chosen_severities:
        print("No valid severities provided. Valid options are: low|medium|high|critical separated by commas if you want multiple")
        return None

    # Create a dictionary that contains a list of vulnerabilities for each chosen severity
    severity_dict = {}
    for s in chosen_severities:
        severity_dict[s] = []

    return severity_dict

def load_snyk_data(filename):
    """
    Load the Snyk JSON data from the scan. Expected in local working directory as output from a scan.

    Args:
        filename (string): A list of command-line arguments, where argv[1] should contain 
                     a comma-separated string of severities (e.g. "critical,high,medium").

    Returns:
        dict or None: A dictionary representing the scan results, or None if the file is not found.
    """
    # Open the snyk.json from the scan
    try:
        with open(filename, 'r') as f:
            snyk_data = json.load(f)
    except FileNotFoundError:
        print("No Snyk JSON results found")
        return None
    return snyk_data

def process_vulnerabilities(severity_dict, vulnerabilities):
    """
    Processes a list of vulnerabilities by filtering against the chosen severities and outputs a formatted title and body as a tuple for a gh issue.
    Args:
        severity_dict (dict): A dictionary where keys are severity levels (e.g., 'low', 'medium', 'high') 
                              and values are lists of vulnerabilities.
        vulnerabilities (list): A list of vulnerability dicts, each containing details for the vulnerability.
    Returns:
        tuple: A tuple containing:
            - title (str): A string summarizing the number of vulnerabilities found for each chosen severity level. 
            - issue_body (str): A formatted string detailing the vulnerabilities.
    """
    issue_body = ""
    processed_id = set()

    # Loop through vulnerabilities and add to severity_dict lists
    for v in vulnerabilities:
        if v.get('severity') in severity_dict:
            # skip duplicate vulnerabilities (same vulnerabilities from different dependency paths)
            if v.get('id') in processed_id:
                continue
            # Add first line of severity for the github issue
            if not severity_dict[v.get('severity')]:
                severity_dict[v.get('severity')].append(f"### Security Issues Found: {v.get('severity')} severity\n\n")

            # Extract required fields from vulnerability and construct string to add
            temp_issue_body = ""
            temp_issue_body += f"  - {v.get('title')}\n"
            temp_issue_body += f"    - ID: {v.get('id')}\n"
            temp_issue_body += f"    - Package@Version: {v.get('packageName')}@{v.get('version')}\n\n"

            # Add vuln to list, update processed_id
            severity_dict[v.get('severity')].append(temp_issue_body)
            processed_id.add(v.get('id'))

    severity_score = ""
    final_body = ""
    # Construct final github issue title and body
    for key in severity_dict.keys():
        if severity_dict[key]:
            severity_score += f", {len(severity_dict[key]) - 1} {key}"
            final_body += "".join(severity_dict[key])

    if final_body:
        issue_body = final_body
    else:
        issue_body = "No Security Issues Found"

    return severity_score, issue_body

def create_github_issue(severity_score, issue_body):
    """
    Create a GitHub issue describing the results of a scan.
    This function uses the GitHub API to create an issue in the specified repository.
    The repository, branch name, and GitHub token are retrieved from environment variables which are used to create the issue.
    
    Args:
        severity_score (str): The severity score of the issue, used to generate the issue title.
        issue_body (str): The body content of the issue. If "No Security Issues Found", a different title is used.
    Raises:
        requests.exceptions.HTTPError: If the HTTP request to create the issue fails.
    Returns:
        None
    """
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    branch_name = os.environ.get("BRANCH_NAME")

    if issue_body != "No Security Issues Found":
        # Strip the first comma and space from the severity_score
        title = f"Snyk Scan: {severity_score[1:]} vulnerabilities in {branch_name} branch"
    else:
        title = f"Snyk Scan: No vulnerabilities found in {branch_name} branch"

    # Setting up POST request
    url = f"https://api.github.com/repos/{repo}/issues" # issues need to be enabled in the repo as a feature otherwise 410 error
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    payload = {
        "title": title,
        "body": issue_body
    }

    # Send the POST request to create the issue
    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()
    print(f"Issue created: {response.json()['html_url']}")

def main():
    # Parse severity levels provided as arguments
    severity_dict = parse_severities(sys.argv)
    if severity_dict is None:
        return
    
    # Load vulnerabilities from snyk.json
    snyk_data = load_snyk_data('snyk.json')
    
    # If the data is None the script fails
    try:
        vulnerabilities = snyk_data.get("vulnerabilities", [])
    except Exception as e:
        print(f"Error loading vulnerabilities from snyk.json: {e}")
        return

    # Process vulnerabilities and create GitHub issue
    severity_score, issue_body = process_vulnerabilities(severity_dict, vulnerabilities)
    create_github_issue(severity_score, issue_body)

if __name__ == "__main__":
    main()
