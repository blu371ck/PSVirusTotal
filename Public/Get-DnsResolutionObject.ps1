function Get-DnsResolutionObject {
   <#
    .SYNOPSIS
        Retrieves a DNS resolution object from VirusTotal. https://docs.virustotal.com/reference/resolution-object.
    .DESCRIPTION
        Retrieves a DNS resolution object from VirusTotal. https://docs.virustotal.com/reference/resolution-object.
    .PARAMETER Id
        The resolution objects ID. A resolution object ID is made by appending the IP and the domain it resolves to together.
    .EXAMPLE
        Get-DnsResolutionObject -Id 142.250.191.206google.com
        # This will get DNS resolution object for Google.com.
    #> 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Domain to get report for.")]
        [string]$Id
    )

    try {
        # Retrieve the API key from private helper function.
        $apiKey = Get-ApiKey

        # Create headers object to contain API key.
        $headers = @{
            "x-apikey" = $apiKey;
            "Accept" = "application/json";
        }

        # Build the URI and notify the user request is about to begin.
        $uri = "https://www.virustotal.com/api/v3/resolutions/$Id"
        Write-Host "Fetching resolution object from VirusTotal for '$Id'..."
        
        # Use Invoke-RestMethod to automatically parse response JSON
        $responseObject = Invoke-RestMethod -Uri $uri -Method GET -Headers $headers
        
        $responseObject | ConvertTo-Json -Depth 100
    }
    catch {
        Write-Error "Failed to get resolution object from VirusTotal for '$Id'. Error: $_"
    }
}