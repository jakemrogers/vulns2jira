# Python Implementation

This is the Python implementation of Vulns2Jira, designed for cross-platform environments and teams familiar with Python.

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

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

For detailed setup instructions, see the [common setup guide](../docs/setup.md).

## Usage

Run the script:
```bash
python vulns2jira.py
```

The script will:
1. Fetch new vulnerabilities from Microsoft Defender
2. Create Jira tickets for each vulnerability
3. Log the results to `vulns2jira.log`

## Features

- Cross-platform compatibility
- Environment variable configuration
- Comprehensive error handling
- Detailed logging
- Rate limiting and token management
- Type hints for better code maintainability

## Dependencies

- msal: Microsoft Authentication Library
- requests: HTTP library
- jira: Jira API client
- python-dotenv: Environment variable management

## Error Handling

The script includes comprehensive error handling:
- Authentication errors
- API rate limiting
- Network issues
- Invalid responses
- File system errors

All errors are logged to `vulns2jira.log` with detailed information.

## Development

To contribute to the Python implementation:

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install development dependencies:
```bash
pip install -r requirements.txt
```

3. Make your changes and test thoroughly

4. Submit a pull request

## Security Notes

- Never commit the `.env` file
- Keep your API tokens and secrets secure
- Regularly rotate your client secrets and API tokens
- Consider using a secure secret management solution for production use 