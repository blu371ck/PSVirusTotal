function Set-IpAddressVote {
   <#
    .SYNOPSIS
        Submits a vote to VirusTotal for a provided IpAddress. The vote is either
        'malicious' or 'harmless'
    .DESCRIPTION
        This function submits a users vote to VirusTotal for an IP address.
    .PARAMETER IpAddress
        The IP address being voted on.
    .PARAMETER Vote
        Your submitted vote, either 'malicious' or 'harmless'.
    .EXAMPLE
        Set-IpAddressVote -IpAddress <IP_ADDRESS_HERE> -Verdict <VERDICT>
    #> 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Ip Address to submit a vote on.")]
        [ipaddress]$IpAddress,
        [Parameter(Mandatory=$true, HelpMessage="Verdict decision, 'harmless' or 'malicious'.")]
        [ValidateSet(
            'harmless',
            'malicious'
        )]
        [string]$Verdict
    )

    try {
        # Retrieve the API key from private helper function.
        $apiKey = Get-ApiKey

        # documentation on this api added the "accept: application/json" so we do the same.
        $headers = @{
            "x-apikey" = $apiKey;
            "Accept" = "application/json"
        }

        $data = @{
            data = @{
                type    = 'vote'
                attributes = @{
                    verdict = $Verdict
                }
            }
        }

        # Build the URI and notify the user request is about to begin.
        $uri = "https://www.virustotal.com/api/v3/ip_addresses/$IpAddress/votes"
        Write-Host "Submitting verdict '$Verdict' for '$IpAddress' to VirusTotal..."

        # Use Invoke-RestMethod to automatically parse response JSON
        $responseObject = Invoke-RestMethod -Uri $uri -Method POST -Headers $headers -ContentType 'application/json' -Body ($data | ConvertTo-Json)

        $responseObject | ConvertTo-Json -Depth 100
    }
    catch {
        Write-Error "Failed to submit verdict to VirusTotal for '$IpAddress'. Error: $_"
    }
}