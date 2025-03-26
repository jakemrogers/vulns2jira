#Requires -Version 7.0
#Requires -Modules MSAL.PS, PSJira

# Configure logging
$logFile = "vulns2jira.log"
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $Level - $Message"
    Add-Content -Path $logFile -Value $logMessage
    Write-Host $logMessage
}

# Load configuration
try {
    $config = Get-Content -Path "config.json" -Raw | ConvertFrom-Json
} catch {
    Write-Log "Failed to load config.json: $_" -Level "ERROR"
    throw
}

class DefenderAPI {
    [string]$TenantId
    [string]$ClientId
    [string]$ClientSecret
    [string]$Authority
    [string[]]$Scope
    [string]$ApiUrl
    [string]$Token

    DefenderAPI([string]$tenantId, [string]$clientId, [string]$clientSecret) {
        $this.TenantId = $tenantId
        $this.ClientId = $clientId
        $this.ClientSecret = $clientSecret
        $this.Authority = "https://login.microsoftonline.com/$tenantId"
        $this.Scope = @("https://api.securitycenter.microsoft.com/.default")
        $this.ApiUrl = "https://api.securitycenter.microsoft.com/api"
    }

    [string]GetToken() {
        if ($this.Token) { return $this.Token }

        try {
            $token = Get-MsalToken -ClientId $this.ClientId `
                                 -ClientSecret (ConvertTo-SecureString $this.ClientSecret -AsPlainText -Force) `
                                 -TenantId $this.TenantId `
                                 -Scopes $this.Scope

            if ($token) {
                $this.Token = $token.AccessToken
                return $this.Token
            }
        } catch {
            Write-Log "Failed to get token: $_" -Level "ERROR"
            throw
        }
    }

    [object[]]GetVulnerabilities([int]$daysBack = 1) {
        try {
            $headers = @{
                'Authorization' = "Bearer $($this.GetToken())"
                'Content-Type' = 'application/json'
            }

            $endDate = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
            $startDate = (Get-Date).AddDays(-$daysBack).ToString("yyyy-MM-ddTHH:mm:ssZ")

            $query = @{
                filter = "discoveredTime gt $startDate and discoveredTime lt $endDate"
                select = @(
                    "id",
                    "title",
                    "description",
                    "severity",
                    "cvssV3",
                    "exposedMachines",
                    "publishedOn",
                    "discoveredTime"
                )
            }

            $response = Invoke-RestMethod -Uri "$($this.ApiUrl)/vulnerabilities" `
                                        -Method Post `
                                        -Headers $headers `
                                        -Body ($query | ConvertTo-Json)

            return $response.value
        } catch {
            Write-Log "Error fetching vulnerabilities: $_" -Level "ERROR"
            throw
        }
    }
}

class JiraAPI {
    [string]$Url
    [string]$Email
    [string]$ApiToken
    [string]$ProjectKey

    JiraAPI([string]$url, [string]$email, [string]$apiToken, [string]$projectKey) {
        $this.Url = $url
        $this.Email = $email
        $this.ApiToken = $apiToken
        $this.ProjectKey = $projectKey

        # Initialize PSJira connection
        Set-JiraConfigServer -Server $url
        Set-JiraConfigToken -Token $apiToken
    }

    [string]CreateVulnerabilityTicket([object]$vuln) {
        try {
            $description = @"
*Vulnerability Details*

*Title:* $($vuln.title)
*Severity:* $($vuln.severity)
*CVSS v3:* $($vuln.cvssV3 ?? 'N/A')
*Published On:* $($vuln.publishedOn ?? 'N/A')
*Discovered On:* $($vuln.discoveredTime ?? 'N/A')
*Affected Machines:* $($vuln.exposedMachines.Count)

*Description:*
$($vuln.description ?? 'No description available')

*Technical Details:*
$($vuln | ConvertTo-Json -Depth 10)
"@

            $issue = @{
                project = $this.ProjectKey
                summary = "Security Vulnerability: $($vuln.title)"
                description = $description
                issuetype = @{ name = "Bug" }
                priority = $this.MapSeverityToPriority($vuln.severity)
            }

            $jiraIssue = New-JiraIssue -Fields $issue
            Write-Log "Created Jira ticket $($jiraIssue.key) for vulnerability $($vuln.id)"
            return $jiraIssue.key
        } catch {
            Write-Log "Failed to create Jira ticket for vulnerability $($vuln.id): $_" -Level "ERROR"
            throw
        }
    }

    [object]MapSeverityToPriority([string]$severity) {
        $severityMap = @{
            'Critical' = @{ name = 'Highest' }
            'High' = @{ name = 'High' }
            'Medium' = @{ name = 'Medium' }
            'Low' = @{ name = 'Low' }
        }
        return $severityMap[$severity] ?? @{ name = 'Medium' }
    }
}

function Main {
    try {
        # Initialize APIs
        $defender = [DefenderAPI]::new(
            $config.MDE.TenantId,
            $config.MDE.ClientId,
            $config.MDE.ClientSecret
        )

        $jira = [JiraAPI]::new(
            $config.Jira.Url,
            $config.Jira.Email,
            $config.Jira.ApiToken,
            $config.Jira.ProjectKey
        )

        # Get vulnerabilities from the last 24 hours
        $vulnerabilities = $defender.GetVulnerabilities(1)
        Write-Log "Found $($vulnerabilities.Count) new vulnerabilities"

        # Create Jira tickets for each vulnerability
        foreach ($vuln in $vulnerabilities) {
            try {
                $ticketKey = $jira.CreateVulnerabilityTicket($vuln)
                Write-Log "Successfully created ticket $ticketKey for vulnerability $($vuln.id)"
            } catch {
                Write-Log "Failed to process vulnerability $($vuln.id): $_" -Level "ERROR"
                continue
            }
        }
    } catch {
        Write-Log "Script failed: $_" -Level "ERROR"
        throw
    }
}

# Run the script
Main 