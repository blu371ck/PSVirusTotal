function Get-DomainObjectDescriptors {
    <#
    .SYNOPSIS
        Retrieves related object descriptors for a domain from VirusTotal.
    .DESCRIPTION
        This function queries the VirusTotal API for object descriptors related to a specific domain.
        It handles pagination automatically by following the continuation cursor to retrieve all available results.
    .PARAMETER Domain
        The domain for which to retrieve related objects.
    .PARAMETER Relationship
        The type of relationship to query. Press Tab to see a list of valid options.
    .PARAMETER Limit
        The number of results to retrieve per API request. The default is 10.
    .PARAMETER OutFile
        Specifies a file path to save the JSON report to. If omitted, results are written to the console.
    .EXAMPLE
        Get-DomainObjectDescriptors -Domain google.com -Relationship resolutions
    .EXAMPLE
        Get-DomainObjectDescriptors -Domain google.com -Relationship communicating_files -Limit 100 -OutFile "C:\Reports\cf.json"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Domain to get objects on.")]
        [string]$Domain,

        [Parameter(Mandatory=$true, HelpMessage="Relationships to search for: https://docs.virustotal.com/reference/domains-object#relationships")]
        [ValidateSet(
            'caa_records',
            'cname_records',
            'comments',
            'communicating_files',
            'downloaded_files',
            'graphs',
            'historical_ssl_certificates',
            'historical_whois',
            'immediate_parent',
            'mx_records',
            'ns_records',
            'parent',
            'referrer_files',
            'related_comments',
            'related_references',
            'related_threat_actors',
            'resolutions',
            'soa_records',
            'siblings',
            'subdomains',
            'urls',
            'user_votes'
        )]
        [string]$Relationship,

        [Parameter(Mandatory=$false, HelpMessage="Maximum number of objects to retrieve from the domain.")]
        [int]$Limit = 10,

        [Parameter(Mandatory=$false, HelpMessage="File path to store results to.")]
        [string]$OutFile
    )

    try {
        $apiKey = Get-ApiKey
        $headers = @{ 
            "x-apikey" = $apiKey;
            'Accept' = 'application/json'; 
        }
        
        # This list will store all the results from all pages.
        $allResults = [System.Collections.Generic.List[object]]::new()
        $cursor = $null
        $pageCount = 1

        Write-Host "Fetching relationship '$Relationship' for '$Domain'..."

        do {
            # Construct the base URI for the API request.
            $uriTemplate = 'https://www.virustotal.com/api/v3/domains/{0}/relationships/{1}?limit={2}'
            $baseUri = $uriTemplate -f $Domain, $Relationship, $Limit
            # If a cursor exists from a previous iteration, add it to the URI.
            $uri = if ($cursor) { "$baseUri&cursor=$cursor" } else { $baseUri }

            Write-Verbose "Querying page $pageCount with URI: $uri"
            $response = Invoke-RestMethod -Uri $uri -Method GET -Headers $headers

            if ($response.data) {
                # Add the data from the current page to our results list.
                $allResults.AddRange($response.data)
                Write-Host "Retrieved $($response.data.Count) results..."
            }

            # Check if the API response includes a cursor for the next page.
            $cursor = $response.meta.cursor
            
            if ($cursor) {
                Write-Host "Continuation cursor found, fetching next page..."
                $pageCount++
            }

        } while ($cursor -and $allResults.Count -lt $Limit) # The loop continues as long as the API provides a cursor.

        Write-Host "Finished fetching. Total results: $($allResults.Count)."

        if ($PSBoundParameters.ContainsKey('OutFile')) {
            Write-Verbose "Saving results to path: $OutFile"
            $allResults | ConvertTo-Json -Depth 100 | Out-File -FilePath $OutFile -Encoding utf8
            Write-Host "Results successfully saved to '$OutFile'."
        }
        else {
            $allResults | ConvertTo-Json
        }
    }
    catch {
        Write-Error "Failed to get related objects for '$Domain'. Error: $_"
    }
}
