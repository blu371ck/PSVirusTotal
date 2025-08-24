function Set-ApiKey {
   <#
    .SYNOPSIS
        Securely saves or overwrites the VirusTotal API key for future use.
    .DESCRIPTION
        This function takes a VirusTotal API key, converts it to a SecureString,
        and saves it to an encrypted XML file. If a key file already exists,
        it will prompt for confirmation before overwriting it.
    .PARAMETER ApiKey
        Your personal VirusTotal API key.
    .PARAMETER Force
        Overwrites the existing API key file without prompting for confirmation.
    .EXAMPLE
        Set-VTApiKey -ApiKey 'your_long_api_key_here'
        # Prompts for confirmation if a key file already exists.

    .EXAMPLE
        Set-VTApiKey -ApiKey 'a_new_api_key' -Force
        # Overwrites the existing key file without asking.
    #> 
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Enter your VirusTotal API key.")]
        [string]$ApiKey,
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    try {
        $configPath = Join-Path -Path $env:APPDATA -ChildPath "VTPowerShell"
        $keyFilePath = Join-Path -Path $configPath -ChildPath "apikey.xml"

        $shouldProceed = $true
        
        if ((Test-Path -Path $keyFilePath) -and (-not $Force.IsPresent)) {
            $target = "the existing API key file at '$keyFilePath'"
            $action = "Overwrite"

            if (-not ($PSCmdlet.ShouldProcess($target, $action))) {
                $shouldProceed = $false
                Write-Host "Operation cancelled by user."
            }
        }

        if ($shouldProceed) {
            if (-not (Test-Path -Path $configPath)) {
                Write-Verbose "Configuration directory not found. Creating it at: $configPath"
                New-Item -Path $configPath -ItemType Directory -Force | Out-Null
            }

            Write-Verbose "Converting API Key to a secure string."
            $secureKey = ConvertTo-SecureString -String $ApiKey -AsPlainText -Force

            Write-Verbose "Saving encrypted key to: $keyFilePath"
            $secureKey | Export-CliXml -Path $keyFilePath

            Write-Host "VirusTotal API key has been securely saved."
            Write-Host "Operation Complete"
        }
    }
    catch {
        Write-Error "Failed to save the API key. Error: $_"
    }
}