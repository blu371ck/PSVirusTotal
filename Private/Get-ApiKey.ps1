function Get-ApiKey {
    <#
    .SYNOPSIS
        Retrieves and decrypts the saved VirusTotal API key. (Internal use only)
    .DESCRIPTION
        This private function locates the encrypted API key file, imports the SecureString,
        and converts it back to a plain-text string for use in other module commands.
        If the key file is not found, it will throw an error.
    .OUTPUTS
        System.String
        Returns the plain-text VirusTotal API key.
    .NOTES
        This is a private function and is not intended to be called directly by the end-user.
    #>
    [CmdletBinding()]
    param()

    try {
        # Define the path to the key file, ensuring it matches the Set-VTApiKey location.
        $configPath = Join-Path -Path $env:APPDATA -ChildPath "VTPowerShell"
        $keyFilePath = Join-Path -Path $configPath -ChildPath "apikey.xml"

        if (-not (Test-Path -Path $keyFilePath)) {
            # Use Throw to create a terminating error if the key file doesn't exist.
            throw "VirusTotal API key file not found at '$keyFilePath'. Please run Set-VTApiKey to configure the module."
        }

        Write-Verbose "Importing encrypted API key from: $keyFilePath"
        $secureKey = Import-CliXml -Path $keyFilePath

        # To decrypt a SecureString, we need to use the PSCredential object as an intermediary.
        # We create a dummy credential, then extract the password in plain text.
        $credential = New-Object System.Management.Automation.PSCredential ('dummyuser', $secureKey)
        $apiKey = $credential.GetNetworkCredential().Password

        # Return the plain-text key.
        return $apiKey
    }
    catch {
        # Re-throw the error to ensure the calling function knows something went wrong.
        throw "Failed to retrieve the VirusTotal API key. Error: $_"
    }
}