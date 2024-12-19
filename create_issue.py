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
    
    severity_dict = {}
    for s in chosen_severities:
        severity_dict[s] = []

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

    #filtered_vulns = [v for v in vulnerabilities if v.get('severity') in chosen_severities]
    vuln_found = None
    issue_body = ""
    for v in vulnerabilities:
        if v.get('severity') in severity_dict:
            if not severity_dict[v.get('severity')]:
                #add the first line of the issue severity
                severity_dict[v.get('severity')].append(f"### {v.get('severity')} Security Issues Found\n\n")
            
            issue_body += f"  - Title: {v.get('title')}\n"
            issue_body += f"    - ID: {v.get('id')}\n"
            issue_body += f"    - Package: {v.get('packageName')}\n"
            issue_body += f"    - Affected Version: {v.get('version')}\n\n"
            severity_dict[v.get('severity')].append(issue_body)
            issue_body = ""
    
    for key in severity_dict.keys():
        if severity_dict[key]:
            issue_body += "".join(severity_dict[key])

    if not issue_body:
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
        "title": f"Snyk Scan Results: {data.get('summary')}",
        "body": issue_body
    }

    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()  # Will raise an error if something went wrong
    print(f"Issue created: {response.json()['html_url']}")

if __name__ == "__main__":
    main()
