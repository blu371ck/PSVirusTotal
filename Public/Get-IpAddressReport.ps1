function Get-IpAddressReport {
   <#
    .SYNOPSIS
        Retrieves a VirusTotal report for provided IP address.
    .DESCRIPTION
        This function requests an IP address report from VirusTotal.
    .PARAMETER IpAddress
        The IP address to request a VirusTotal report for.
    .EXAMPLE
        Get-IpAddressReport -IpAddress <IP_ADDRESS_HERE>
        # This command retrieves the report for the IP address <IP_ADDRESS_HERE>
    .EXAMPLE
        Get-IpAddressReport -IpAddress <IP_ADDRESS_HERE> -OutFile <FILE_LOCATION_HERE>
        # This command retrieves the report for the IP address <IP_ADDRESS_HERE> and
        # saves it in <FILE_LOCATION_HERE>
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
        $apiKey = Get-VTApiKey

        # Create headers object to contain API key.
        $headers = @{
            "x-apikey" = $apiKey
        }

        # Build the URI and notify the user request is about to begin.
        $uri = "https://www.virustotal.com/api/v3/ip_addresses/$IpAddress"
        Write-Host "Fetching report from VirusTotal for '$IpAddress'..."
        
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