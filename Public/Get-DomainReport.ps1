function Get-DomainReport {
   <#
    .SYNOPSIS
        Retrieves a VirusTotal report for provided domain.
    .DESCRIPTION
        Retrieves a VirusTotal report for provided domain.
    .PARAMETER Domain
        The domain to request a VirusTotal report for.
    .EXAMPLE
        Get-DomainReport -Domain <DOMAIN>
        # This command retrieves the report for the domain <DOMAIN>
    .EXAMPLE
        Get-DomainReport -Domain <DOMAIN> -OutFile <FILE_LOCATION_HERE>
        # This command retrieves the report for the domain <DOMAIN> and
        # saves it in <FILE_LOCATION_HERE>
    #> 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Domain to get report for.")]
        [string]$Domain,
        [Parameter(Mandatory=$false, HelpMessage="File path to store results in.")]
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
        $uri = "https://www.virustotal.com/api/v3/domains/$Domain"
        Write-Host "Fetching report from VirusTotal for '$Domain'..."
        
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
        Write-Error "Failed to get report from VirusTotal for '$Domain'. Error: $_"
    }
}