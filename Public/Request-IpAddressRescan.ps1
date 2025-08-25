function Request-IpAddressRescan {
   <#
    .SYNOPSIS
        Requests an IP address be re-scanned by VirusTotal. Updating its information. This
        command returns the JSON result and does not redirect to the new url. 
    .DESCRIPTION
        This function requests an IP address be re-scanned by VirusTotal.
    .PARAMETER IpAddress
        The IP address to request VirusTotal to re-scan
    .EXAMPLE
        Get-IpAddressReport -IpAddress <IP_ADDRESS_HERE>
    #> 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Ip Address to re-scan")]
        [ipaddress]$IpAddress
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
        $uri = "https://www.virustotal.com/api/v3/ip_addresses/$IpAddress/analyse"
        Write-Host "Requesting a re-scan from VirusTotal for '$IpAddress'..."

        # Use Invoke-RestMethod to automatically parse response JSON
        $responseObject = Invoke-RestMethod -Uri $uri -Method POST -Headers $headers

        $responseObject | ConvertTo-Json -Depth 100
    }
    catch {
        Write-Error "Failed to request a re-scan from VirusTotal for '$IpAddress'. Error: $_"
    }
}