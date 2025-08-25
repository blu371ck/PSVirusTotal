function Get-DomainVotes {
   <#
    .SYNOPSIS
        Retrieves VirusTotal vote objects from a domain.
    .DESCRIPTION
        This function requests a domains Votes object from VirusTotal.
    .PARAMETER Domain
        The domain to request a VirusTotal votes for.
    .PARAMETER OutFile
        A file path to save the response in.
    .EXAMPLE
        Get-DomainVotes -Domain <DOMAIN>
        # This command retrieves the vote objects for the domain <DOMAIN>
    #> 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Domain to get votes on.")]
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
        $uri = "https://www.virustotal.com/api/v3/domains/$Domain/votes"
        Write-Host "Fetching vote objects from VirusTotal for '$Domain'..."
        
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
        Write-Error "Failed to get votes from VirusTotal for '$Domain'. Error: $_"
    }
}