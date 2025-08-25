function Get-DomainComments {
   <#
    .SYNOPSIS
        Retrieves community comments for a domain from VirusTotal.
    .DESCRIPTION
        This function retrieves community comments for a given domain from the VirusTotal API.
        It automatically handles pagination to retrieve all available comments.
    .PARAMETER Domain
        The domain to request VirusTotal comments for.
    .PARAMETER Limit
        The number of comments to retrieve per API request. Defaults to 10
    .PARAMETER OutFile
        Specifies a file path to save the comments to.
    .EXAMPLE
        Get-DomainComments -Domain "google.com"
        # This command retrieves all comments for the domain "google.com".
    #> 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Domain to get comments on.")]
        [string]$Domain,

        [Parameter(Mandatory=$false, HelpMessage="Number of comments to retrieve per page.")]
        [int]$Limit = 10,

        [Parameter(Mandatory=$false, HelpMessage="File path to store results in.")]
        [string]$OutFile
    )   

    try {
        # Retrieve the API key from the private helper function.
        $apiKey = Get-ApiKey

        $headers = @{
            "x-apikey" = $apiKey;
            "Accept" = "application/json"
        }

        # This list will store all the results from all pages.
        $allResults = [System.Collections.Generic.List[object]]::new()
        $cursor = $null
        $pageCount = 1

        Write-Host "Fetching comments from VirusTotal for '$Domain'..."

        do {
            $baseUri = "https://www.virustotal.com/api/v3/domains/$Domain/comments?limit=$Limit"
            $uri = if ($cursor) { "$baseUri&cursor=$cursor" } else { $baseUri }

            Write-Verbose "Querying page $pageCount with URI: $uri"
            $response = Invoke-RestMethod -Uri $uri -Method GET -Headers $headers

            if ($response.data) {
                $allResults.AddRange($response.data)
                Write-Host "Retrieved $($response.data.Count) comments..."
            }

            # Check for a cursor to get the next page of results.
            $cursor = $response.meta.cursor
            
            if ($cursor) {
                Write-Host "Continuation cursor found, fetching next page..."
                $pageCount++
            }

        } while ($cursor -and $allResults.Count -lt $Limit)

        Write-Host "Finished fetching. Total comments: $($allResults.Count)."
        
        if ($PSBoundParameters.ContainsKey('OutFile')) {
            Write-Verbose "Saving comments to path: $OutFile"
            $allResults | ConvertTo-Json -Depth 100 | Out-File -FilePath $OutFile -Encoding utf8
            Write-Host "Comments successfully saved to '$OutFile'."
        }
        else {
            # Return the rich PowerShell object to the pipeline.
            $allResults | ConvertTo-Json
        }
    }
    catch {
        Write-Error "Failed to get comments from VirusTotal for '$Domain'. Error: $_"
    }
}
