function Get-IpAddressComments {
   <#
    .SYNOPSIS
        Retrieves VirusTotal IP address comments.
    .DESCRIPTION
        This function requests the comments from an IP address on VirusTotal.
    .PARAMETER IpAddress
        The IP address to request VirusTotal comments on.
    .PARAMETER Limit
        The maximum limit of comments to retrieve. Defaults to 10
    .EXAMPLE
        Get-IpAddressReport -IpAddress <IP_ADDRESS_HERE>
        # This command retrieves the report for the IP address <IP_ADDRESS_HERE>
    #> 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Ip Address to get report for")]
        [ipaddress]$IpAddress,
        [Parameter(Mandatory=$false, HelpMessage="Maximum number of comments to retrieve")]
        [int]$Limit = 10,
        [Parameter(Mandatory=$false, HelpMessage="File path to store results in")]
        [string]$OutFile
    )   

    try {
        # Retrieve the API key from private helper function.
        $apiKey = Get-VTApiKey

        # documentation on this api added the "accept: application/json" so we do the same.
        $headers = @{
            "x-apikey" = $apiKey;
            "Accept" = "application/json"
        }

        # Build the URI and notify the user request is about to begin.
        $uri = "https://www.virustotal.com/api/v3/ip_addresses/$IpAddress/comments?limit=$Limit"
        Write-Host "Fetching '$Limit' comments from VirusTotal for '$IpAddress'..."

        # Use Invoke-RestMethod to automatically parse response JSON
        $responseObject = Invoke-RestMethod -Uri $uri -Method GET -Headers $headers
        
        # If the -OutFile switch is provided, write the output to that path instead
        if ($PSBoundParameters.ContainsKey('OutFile')) {
            Write-Verbose "Saving comments to path: $OutFile"
            $responseObject | ConvertTo-Json -Depth 100 | Out-File -FilePath $OutFile -Encoding utf8
            Write-Host "Comments successfully saved to '$OutFile'."
        } # else just print it out to screen
        else {
            $responseObject | ConvertTo-Json -Depth 100
        }
    }
    catch {
        Write-Error "Failed to get comments from VirusTotal for '$IpAddress'. Error: $_"
    }
}