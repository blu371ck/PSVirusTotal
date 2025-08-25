function Get-IpAddressVotes {
   <#
    .SYNOPSIS
        Retrieves VirusTotal vote objects from an IP address.
    .DESCRIPTION
        This function requests an IP address Votes object from VirusTotal.
    .PARAMETER IpAddress
        The IP address to request a VirusTotal report for.
    .PARAMETER OutFile
        A file path to save the response in.
    .EXAMPLE
        Get-IpAddressVotes -IpAddress <IP_ADDRESS_HERE>
        # This command retrieves the vote objects for the IP address <IP_ADDRESS_HERE>
    #> 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Ip Address to get report for")]
        [ipaddress]$IpAddress,
        [Parameter(Mandatory=$false)]
        [string]$OutFile
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
        $uri = "https://www.virustotal.com/api/v3/ip_addresses/$IpAddress/votes"
        Write-Host "Fetching vote objects from VirusTotal for '$IpAddress'..."
        
        # Use Invoke-RestMethod to automatically parse response JSON
        $responseObject = Invoke-RestMethod -Uri $uri -Method GET -Headers $headers
        
        # If the -OutFile switch is provided, write the output to that path instead
        if ($PSBoundParameters.ContainsKey('OutFile')) {
            Write-Verbose "Saving report to path: $OutFile"
            $responseObject | ConvertTo-Json -Depth 100 | Out-File -FilePath $OutFile -Encoding utf8
            Write-Host "Report successfully saved to '$OutFile'."
        } # else just print it out to screen
        else {
            $responseObject | ConvertTo-Json -Depth 100
        }
    }
    catch {
        Write-Error "Failed to get report from VirusTotal for '$IpAddress'. Error: $_"
    }
}