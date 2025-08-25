function Add-DomainComment {
   <#
    .SYNOPSIS
        Submits a comment to VirusTotal for a provided domain. 
    .DESCRIPTION
        Submits a comment to VirusTotal for a provided domain.
    .PARAMETER Domain
        The domain to comment on.
    .PARAMETER Comment
        Your submitted comment.
    .EXAMPLE
        Add-DomainComment -Domain <DOMAIN> -Comment <COMMENT>
    #> 
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, HelpMessage="Domain to comment on.")]
        [string]$Domain,
        [Parameter(Mandatory=$true, HelpMessage="Comment string to submit for domain.")]
        [string]$Comment
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
                type    = 'comment'
                attributes = @{
                    text = $Comment
                }
            }
        }

        # Build the URI and notify the user request is about to begin.
        $uri = "https://www.virustotal.com/api/v3/domains/$Domain/comments"
        Write-Host "Submitting comment on '$Domain' to VirusTotal..."

        # Use Invoke-RestMethod to automatically parse response JSON
        $responseObject = Invoke-RestMethod -Uri $uri -Method POST -Headers $headers -ContentType 'application/json' -Body ($data | ConvertTo-Json)

        $responseObject | ConvertTo-Json -Depth 100
    }
    catch {
        Write-Error "Failed to submit comment to VirusTotal for '$Domain'. Error: $_"
    }
}