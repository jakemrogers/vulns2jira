# MS Defender to Jira Vulnerability Sync (PowerShell)

This PowerShell script automatically creates Jira tickets for new vulnerabilities discovered by Microsoft Defender for Endpoint.

## Prerequisites

- PowerShell 7.0 or higher
- Microsoft Defender for Endpoint API access
- Jira API access
- Azure AD application registration
- Required PowerShell modules:
  - MSAL.PS
  - PSJira

## Setup

1. Install required PowerShell modules:
```powershell
Install-Module -Name MSAL.PS -Force
Install-Module -Name PSJira -Force
```

2. Create a `config.json` file with the following structure:
```json
{
    "MDE": {
        "TenantId": "your_tenant_id",
        "ClientId": "your_client_id",
        "ClientSecret": "your_client_secret"
    },
    "Jira": {
        "Url": "your_jira_url",
        "Email": "your_jira_email",
        "ApiToken": "your_jira_api_token",
        "ProjectKey": "your_project_key"
    }
}
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
```powershell
.\vulns2jira.ps1
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

- Never commit the `config.json` file to version control
- Keep your API tokens and secrets secure
- Regularly rotate your client secrets and API tokens
- Consider using Azure Key Vault or similar for production use 