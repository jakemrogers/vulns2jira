# MS Defender to Jira Vulnerability Sync

This script automatically creates Jira tickets for new vulnerabilities discovered by Microsoft Defender for Endpoint.

## Prerequisites

- Python 3.8 or higher
- Microsoft Defender for Endpoint API access
- Jira API access
- Azure AD application registration

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Create a `.env` file with the following variables:
```
# Microsoft Defender for Endpoint
MDE_TENANT_ID=your_tenant_id
MDE_CLIENT_ID=your_client_id
MDE_CLIENT_SECRET=your_client_secret

# Jira
JIRA_URL=your_jira_url
JIRA_EMAIL=your_jira_email
JIRA_API_TOKEN=your_jira_api_token
JIRA_PROJECT_KEY=your_project_key
```

3. Configure the Azure AD application:
   - Register a new application in Azure AD
   - Grant it the following permissions:
     - Microsoft Defender for Endpoint API: Vulnerability.Read.All
   - Create a client secret and note down the values

4. Configure Jira:
   - Generate an API token from your Jira account
   - Note down your Jira URL and project key

## Usage

Run the script:
```bash
python vulns2jira.py
```

The script will:
1. Fetch new vulnerabilities from Microsoft Defender
2. Create Jira tickets for each vulnerability
3. Log the results to `vulns2jira.log`

## Error Handling

- The script includes comprehensive error handling and logging
- Failed ticket creations are logged with details
- Authentication errors are clearly reported
- Rate limiting is handled automatically

## Security Notes

- Never commit the `.env` file to version control
- Keep your API tokens and secrets secure
- Regularly rotate your client secrets and API tokens 