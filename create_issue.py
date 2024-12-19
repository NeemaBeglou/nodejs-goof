import os
import json
import requests
import sys

def main():
    # Check for severity argument
    if len(sys.argv) < 2:
        print("Usage: python create_issue.py <severities>")
        print("Example: python create_issue.py critical,high,medium")
        return

    # Parse and normalize severity levels
    severities = sys.argv[1].split(',')
    severities = [s.strip().lower() for s in severities]  # Ensure lowercase and strip spaces
    valid_severities = {'low', 'medium', 'high', 'critical'}
    
    # Filter out invalid severities
    chosen_severities = [s for s in severities if s in valid_severities]
    
    #create a dictionary that contains a list of vulnerabilities for each chosen severity
    severity_dict = {}
    for s in chosen_severities:
        severity_dict[s] = []

    if not chosen_severities:
        print("No valid severities provided. Valid options are: low|medium|high|critical separated by commas if you want multiple")
        return
    
    #Open the snyk.json from the scan
    try:
        with open('snyk.json', 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print("No Snyk JSON results found")
        return
    
    vulnerabilities = data.get("vulnerabilities", [])
    issue_body = ""
    processed_id = set()
    
    #Loop through vulnerabilities and add to severity_dict lists
    for v in vulnerabilities:
        if v.get('severity') in severity_dict:
            #skip duplicate vulnerabilities (same vulnerabilities from different dependency paths)
            if v.get('id') in processed_id:
                continue
            #Add first line of severity for the github issue
            if not severity_dict[v.get('severity')]:
                severity_dict[v.get('severity')].append(f"### Security Issues Found: {v.get('severity')} severity\n\n")
            
            #Extract required fields from vulnerability and construct string to add to severity list
            issue_body += f"  - {v.get('title')}\n"
            issue_body += f"    - ID: {v.get('id')}\n"
            issue_body += f"    - Package: {v.get('packageName')}@{v.get('version')}\n\n"
            #issue_body += f"    - Fix Version: {v.get('remediation').get('upgrade').get({v.get('packageName')}@{v.get('version')}).get('upgradeTo')}\n\n" #Future work to add fix version if available
            
            #Add vuln to list, reinitialise issue_body and add to processed_id set
            severity_dict[v.get('severity')].append(issue_body)
            issue_body = ""
            processed_id.add(v.get('id'))
    
    title = ""
    #Construct final github issue title and body
    for key in severity_dict.keys():
        if severity_dict[key]:
            title += f", {len(severity_dict[key]) - 1} {key}"
            issue_body += "".join(severity_dict[key])

    if issue_body:
        title = f"Snyk Scan: {title[1:]} vulnerabilities in {branch_name} branch"
    else:
        issue_body = "No Security Issues Found"
        title = "Snyk Scan: No vulnerabilities found in {branch_name} branch"


    #Create the GitHub issue using built in github action secrets (token is one time use)
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    branch_name = os.environ.get("BRANCH_NAME")

    #Setting up POST request
    url = f"https://api.github.com/repos/{repo}/issues" #issues need to be enabled in the repo as a feature otherwise 410 error
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    payload = {
        "title": title,
        "body": issue_body
    }
    
    #Send the POST request to create the issue
    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()
    print(f"Issue created: {response.json()['html_url']}")

if __name__ == "__main__":
    main()
