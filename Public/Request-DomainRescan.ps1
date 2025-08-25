function Request-DomainRescan {
   <#
    .SYNOPSIS
        Requests a domain be re-scanned by VirusTotal. Updating its information. This
        command returns the JSON result and does not redirect to the results. 
    .DESCRIPTION
        Requests a domain be re-scanned by VirusTotal. Updating its information. 
    .PARAMETER Domain
        The domain to request VirusTotal to re-scan
    .EXAMPLE
        Request-DomainRescan -Domain <DOMAIN>
    #> 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Domain to request re-scan for.")]
        [string]$Domain
    )

    try {
        # Retrieve the API key from private helper function.
        $apiKey = Get-ApiKey

        # documentation on this api added the "accept: application/json" so we do the same.
        $headers = @{
            "x-apikey" = $apiKey;
            "Accept" = "application/json"
        }

        # Build the URI and notify the user request is about to begin.
        $uri = "https://www.virustotal.com/api/v3/domains/$Domain/analyse"
        Write-Host "Requesting a re-scan from VirusTotal for '$Domain'..."

        # Use Invoke-RestMethod to automatically parse response JSON
        $responseObject = Invoke-RestMethod -Uri $uri -Method POST -Headers $headers

        $responseObject | ConvertTo-Json -Depth 100
    }
    catch {
        Write-Error "Failed to request a re-scan from VirusTotal for '$Domain'. Error: $_"
    }
}