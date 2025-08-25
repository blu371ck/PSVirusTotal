function Get-IpAddressObjectDescriptors {
    <#
    .SYNOPSIS
        Retrieves related object descriptors for an IP address from VirusTotal.
    .DESCRIPTION
        This function queries the VirusTotal API for object descriptors related to a specific IP address.
        It handles pagination automatically by following the continuation cursor to retrieve all available results.
    .PARAMETER IpAddress
        The IP address for which to retrieve related object descriptors.
    .PARAMETER Relationship
        The type of relationship to query. Press Tab to see a list of valid options.
    .PARAMETER Limit
        The number of results to retrieve per API request. The default is 10.
    .PARAMETER OutFile
        Specifies a file path to save the JSON report to. If omitted, results are written to the console.
    .EXAMPLE
        Get-IpAddressObjectDescriptors -IpAddress 8.8.8.8 -Relationship resolutions
        # Retrieves all DNS resolutions for 8.8.8.8 and displays them in the console.

    .EXAMPLE
        Get-IpAddressObjectDescriptors -IpAddress 1.1.1.1 -Relationship communicating_files -Limit 100 -OutFile "C:\Reports\cf.json"
        # Retrieves all communicating files for 1.1.1.1, fetching 100 at a time, and saves the full results to a file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="IP Address to get object descriptors for.")]
        [ipaddress]$IpAddress,

        [Parameter(Mandatory=$true, HelpMessage="List of available relationships: https://docs.virustotal.com/reference/ip-object#relationships")]
        [ValidateSet(
            'comments',
            'communicating_files',
            'downloaded_files',
            'graphs',
            'historical_ssl_certificates',
            'historical_whois',
            'related_comments',
            'related_references',
            'related_threat_actors',
            'referrer_files',
            'resolutions',
            'urls'
        )]
        [string]$Relationship,

        [Parameter(Mandatory=$false, HelpMessage="Maximum number of object descriptors to retrieve.")]
        [int]$Limit = 10,

        [Parameter(Mandatory=$false, HelpMessage="File path to store results in.")]
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

        Write-Host "Fetching relationship '$Relationship' for '$IpAddress'..."

        do {
            # Construct the base URI for the API request.
            $uriTemplate = 'https://www.virustotal.com/api/v3/ip_addresses/{0}/relationships/{1}?limit={2}'
            $baseUri = $uriTemplate -f $IpAddress.IPAddressToString, $Relationship, $Limit
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

        } while ($cursor) # The loop continues as long as the API provides a cursor.

        Write-Host "Finished fetching. Total results: $($allResults.Count)."

        if ($PSBoundParameters.ContainsKey('OutFile')) {
            Write-Verbose "Saving results to path: $OutFile"
            $allResults | ConvertTo-Json -Depth 100 | Out-File -FilePath $OutFile -Encoding utf8
            Write-Host "Results successfully saved to '$OutFile'."
        }
        else {
            # Output the combined results to the pipeline.
            return $allResults
        }
    }
    catch {
        Write-Error "Failed to get related objects for '$IpAddress'. Error: $_"
    }
}
