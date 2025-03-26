#!/usr/bin/env python3
import os
import logging
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any

import msal
import requests
from jira import JIRA
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    filename='vulns2jira.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Load environment variables
load_dotenv()

class DefenderAPI:
    def __init__(self):
        self.tenant_id = os.getenv('MDE_TENANT_ID')
        self.client_id = os.getenv('MDE_CLIENT_ID')
        self.client_secret = os.getenv('MDE_CLIENT_SECRET')
        self.authority = f'https://login.microsoftonline.com/{self.tenant_id}'
        self.scope = ['https://api.securitycenter.microsoft.com/.default']
        self.api_url = 'https://api.securitycenter.microsoft.com/api'
        self._token = None

    def get_token(self) -> str:
        """Get access token for Microsoft Defender API."""
        if self._token:
            return self._token

        app = msal.ConfidentialClientApplication(
            client_id=self.client_id,
            client_credential=self.client_secret,
            authority=self.authority
        )

        result = app.acquire_token_silent(self.scope, account=None)
        if not result:
            result = app.acquire_token_for_client(scopes=self.scope)

        if 'access_token' in result:
            self._token = result['access_token']
            return self._token
        else:
            logging.error(f"Failed to get token: {result.get('error_description', 'Unknown error')}")
            raise Exception("Failed to get access token")

    def get_vulnerabilities(self, days_back: int = 1) -> List[Dict[str, Any]]:
        """Fetch vulnerabilities from Microsoft Defender."""
        try:
            headers = {
                'Authorization': f'Bearer {self.get_token()}',
                'Content-Type': 'application/json'
            }

            # Calculate the date range
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days_back)

            # Format dates for the API
            start_date_str = start_date.strftime('%Y-%m-%dT%H:%M:%SZ')
            end_date_str = end_date.strftime('%Y-%m-%dT%H:%M:%SZ')

            # Build the query
            query = {
                "filter": f"discoveredTime gt {start_date_str} and discoveredTime lt {end_date_str}",
                "select": [
                    "id",
                    "title",
                    "description",
                    "severity",
                    "cvssV3",
                    "exposedMachines",
                    "publishedOn",
                    "discoveredTime"
                ]
            }

            response = requests.post(
                f'{self.api_url}/vulnerabilities',
                headers=headers,
                json=query
            )

            if response.status_code == 200:
                return response.json().get('value', [])
            else:
                logging.error(f"Failed to fetch vulnerabilities: {response.status_code} - {response.text}")
                raise Exception(f"API request failed with status code {response.status_code}")

        except Exception as e:
            logging.error(f"Error fetching vulnerabilities: {str(e)}")
            raise

class JiraAPI:
    def __init__(self):
        self.url = os.getenv('JIRA_URL')
        self.email = os.getenv('JIRA_EMAIL')
        self.api_token = os.getenv('JIRA_API_TOKEN')
        self.project_key = os.getenv('JIRA_PROJECT_KEY')
        self.jira = JIRA(
            server=self.url,
            basic_auth=(self.email, self.api_token)
        )

    def create_vulnerability_ticket(self, vuln: Dict[str, Any]) -> str:
        """Create a Jira ticket for a vulnerability."""
        try:
            # Format the description
            description = f"""
*Vulnerability Details*

*Title:* {vuln['title']}
*Severity:* {vuln['severity']}
*CVSS v3:* {vuln.get('cvssV3', 'N/A')}
*Published On:* {vuln.get('publishedOn', 'N/A')}
*Discovered On:* {vuln.get('discoveredTime', 'N/A')}
*Affected Machines:* {len(vuln.get('exposedMachines', []))}

*Description:*
{vuln.get('description', 'No description available')}

*Technical Details:*
{json.dumps(vuln, indent=2)}
"""

            # Create the issue
            issue_dict = {
                'project': self.project_key,
                'summary': f"Security Vulnerability: {vuln['title']}",
                'description': description,
                'issuetype': {'name': 'Bug'},
                'priority': self._map_severity_to_priority(vuln['severity'])
            }

            issue = self.jira.create_issue(fields=issue_dict)
            logging.info(f"Created Jira ticket {issue.key} for vulnerability {vuln['id']}")
            return issue.key

        except Exception as e:
            logging.error(f"Failed to create Jira ticket for vulnerability {vuln['id']}: {str(e)}")
            raise

    def _map_severity_to_priority(self, severity: str) -> Dict[str, str]:
        """Map Microsoft Defender severity to Jira priority."""
        severity_map = {
            'Critical': {'name': 'Highest'},
            'High': {'name': 'High'},
            'Medium': {'name': 'Medium'},
            'Low': {'name': 'Low'}
        }
        return severity_map.get(severity, {'name': 'Medium'})

def main():
    try:
        # Initialize APIs
        defender = DefenderAPI()
        jira = JiraAPI()

        # Get vulnerabilities from the last 24 hours
        vulnerabilities = defender.get_vulnerabilities(days_back=1)
        logging.info(f"Found {len(vulnerabilities)} new vulnerabilities")

        # Create Jira tickets for each vulnerability
        for vuln in vulnerabilities:
            try:
                ticket_key = jira.create_vulnerability_ticket(vuln)
                logging.info(f"Successfully created ticket {ticket_key} for vulnerability {vuln['id']}")
            except Exception as e:
                logging.error(f"Failed to process vulnerability {vuln['id']}: {str(e)}")
                continue

    except Exception as e:
        logging.error(f"Script failed: {str(e)}")
        raise

if __name__ == "__main__":
    main() 