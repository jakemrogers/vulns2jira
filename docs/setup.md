# Setup Instructions

This document contains common setup instructions for both Python and PowerShell implementations of Vulns2Jira.

## Prerequisites

### Microsoft Defender for Endpoint
1. Access to Microsoft Defender for Endpoint API
2. Azure AD application registration with the following permissions:
   - Microsoft Defender for Endpoint API: Vulnerability.Read.All
3. Client credentials (Client ID and Secret)

### Jira
1. Jira instance with API access
2. API token generated from your Jira account
3. Project key where tickets will be created

## Azure AD Application Setup

1. Go to the Azure Portal (https://portal.azure.com)
2. Navigate to Azure Active Directory > App registrations
3. Click "New registration"
4. Fill in the application details:
   - Name: Vulns2Jira
   - Supported account types: Single tenant
5. After registration, note down:
   - Application (client) ID
   - Directory (tenant) ID
6. Create a client secret:
   - Go to "Certificates & secrets"
   - Click "New client secret"
   - Note down the secret value (it's only shown once)
7. Configure API permissions:
   - Go to "API permissions"
   - Click "Add a permission"
   - Choose "Microsoft Graph"
   - Select "Application permissions"
   - Add "Vulnerability.Read.All"
   - Click "Grant admin consent"

## Jira Setup

1. Log in to your Jira instance
2. Go to Account Settings > Security
3. Generate an API token
4. Note down:
   - Your Jira URL
   - Your email address
   - The API token
   - The project key where tickets should be created

## Implementation-Specific Setup

Choose your preferred implementation and follow the specific setup instructions:

- [Python Setup](python/README.md#setup)
- [PowerShell Setup](powershell/README.md#setup)

## Security Best Practices

1. Never commit configuration files containing credentials
2. Use environment variables or secure secret management solutions
3. Regularly rotate API tokens and client secrets
4. Use the principle of least privilege when setting up permissions
5. Monitor API usage and set up alerts for unusual activity
6. Keep the tool and its dependencies updated
7. Review logs regularly for any security concerns

## Troubleshooting

Common issues and solutions:

1. Authentication Failures
   - Verify credentials are correct
   - Check token expiration
   - Ensure proper permissions are granted

2. API Rate Limiting
   - Implement appropriate delays between requests
   - Monitor API usage limits
   - Consider implementing retry logic

3. Network Issues
   - Verify network connectivity
   - Check firewall rules
   - Ensure proper proxy configuration if needed

For implementation-specific issues, refer to the respective README files. 