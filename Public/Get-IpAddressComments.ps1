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
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Ip Address to get comments on.")]
        [ipaddress]$IpAddress,
        [Parameter(Mandatory=$false, HelpMessage="Maximum number of comments to retrieve.")]
        [int]$Limit = 10,
        [Parameter(Mandatory=$false, HelpMessage="File path to store results in.")]
        [string]$OutFile
    )   

    try {
        # Retrieve the API key from private helper function.
        $apiKey = Get-ApiKey

        # documentation on this api added the "accept: application/json" so we do the same.
        $headers = @{
            "x-apikey" = $apiKey;
            "Accept" = "application/json"
        }

        # This list will store all the results from all pages.
        $allResults = [System.Collections.Generic.List[object]]::new()
        $cursor = $null
        $pageCount = 1

        Write-Host "Fetching comments from VirusTotal for '$IpAddress'..."

        do {
            $baseUri = "https://www.virustotal.com/api/v3/ip_addresses/$IpAddress/comments?limit=$Limit"
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

        } while ($cursor -and $allResults -lt $Limit)

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
        Write-Error "Failed to get comments from VirusTotal for '$IpAddress'. Error: $_"
    }
}