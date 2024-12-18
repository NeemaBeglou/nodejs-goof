import os
import json
import requests
import sys

def main():
    # Check for severity argument
    if len(sys.argv) < 2:
        print("Usage: python create_issue.py <severities>")
        print("Example: python create_issue.py critical|high|medium")
        return

    # Parse and normalize severity levels
    severities = sys.argv[1].split('|')
    severities = [s.strip().lower() for s in severities]  # Ensure lowercase and strip spaces
    valid_severities = {'low', 'medium', 'high', 'critical'}
    # Filter out invalid severities
    chosen_severities = [s for s in severities if s in valid_severities]

    if not chosen_severities:
        print("No valid severities provided. Valid options are: low|medium|high|critical")
        return

    try:
        with open('snyk.json', 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print("No Snyk JSON results found")
        return
    
    vulnerabilities = data.get("vulnerabilities", [])
    filtered_vulns = [v for v in vulnerabilities if v.get('severity') in chosen_severities]

    if filtered_vulns:
        issue_body = "### Security Issues Found\n\n"
        for v in filtered_vulns:
            #issue_body = f"- **Severity:** {v.get('severity')}\n"
            issue_body += f"  - ID: {v.get('id')}\n"
            issue_body += f"  - Title: {v.get('title')}\n"
            issue_body += f"  - Package: {v.get('packageName')}@{v.get('version')}\n\n"
    else:
        issue_body = "No Security Issues Found"

    print(issue_body)
    # Create the GitHub issue
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")  # e.g. "owner/repo"

    url = f"https://api.github.com/repos/{repo}/issues"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    payload = {
        "title": "Snyk Scan Results",
        "body": issue_body
    }

    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()  # Will raise an error if something went wrong
    print(f"Issue created: {response.json()['html_url']}")

if __name__ == "__main__":
    main()
