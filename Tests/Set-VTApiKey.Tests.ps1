Describe 'Set-VTApiKey' -Tags 'Unit' {

    BeforeAll {
        $mockApiKey = '12345-abcde-67890-fghij'
        $tempPath = ''
        $configPath = ''
        $keyFilePath = ''


        . "$PSScriptRoot\..\Public\Set-VTApiKey.ps1"

        # Create a temporary directory for our tests to avoid touching the real AppData folder.
        $tempPath = New-Item -Path $env:TEMP -Name "Pester-Test-$(Get-Random)" -ItemType Directory
        $configPath = Join-Path -Path $tempPath.FullName -ChildPath 'VTPowerShell'
        $keyFilePath = Join-Path -Path $configPath -ChildPath 'apikey.xml'

        # Mock the $env:APPDATA variable so the function uses our temporary path.
        # This is the key to isolating the test from the user's real environment.
        Mock -CommandName 'Join-Path' -MockWith {
            param($Path, $ChildPath)
            
            # When the function asks for $env:APPDATA, give it our temp path instead.
            if ($Path -eq $env:APPDATA) {
                return [System.IO.Path]::Combine($tempPath.FullName, $ChildPath)
            }
            # Otherwise, let Join-Path behave normally.
            return [System.IO.Path]::Combine($Path, $ChildPath)
        } -Verifiable
    }

    AfterAll {
        # Clean up the temporary directory and files after all tests are done.
        if (Test-Path $tempPath) {
            Remove-Item -Path $tempPath -Recurse -Force
        }
    }
    
    # Test Case 1: Check if the function creates the configuration directory if it doesn't exist.
    It 'Creates the VTPowerShell directory if it does not exist' {
        Set-VTApiKey -ApiKey $mockApiKey -Force
        Test-Path -Path $configPath | Should -BeTrue
    }

    # Test Case 2: Check if the API key file is created.
    It 'Creates the apikey.xml file' {
        Set-VTApiKey -ApiKey $mockApiKey -Force
        Test-Path -Path $keyFilePath | Should -BeTrue
    }

    # Test Case 3: Verify that the saved key is correct and encrypted.
    It 'Saves the correct API key in an encrypted format' {
        Set-VTApiKey -ApiKey $mockApiKey -Force

        # Import the encrypted key from the file
        $secureKey = Import-CliXml -Path $keyFilePath
        
        # Decrypt the key to verify its contents
        $credential = New-Object System.Management.Automation.PSCredential ('dummyuser', $secureKey)
        $decryptedKey = $credential.GetNetworkCredential().Password

        $decryptedKey | Should -Be $mockApiKey
    }

    # Test Case 4: Ensure the -Force switch overwrites an existing key file.
    It 'Overwrites an existing key file when -Force is used' {
        # Create a dummy file with an old key
        "old-key" | Export-CliXml -Path $keyFilePath

        # Run the function with a new key and the -Force switch
        Set-VTApiKey -ApiKey $mockApiKey -Force

        # The key in the file should now be the new one
        $secureKey = Import-CliXml -Path $keyFilePath
        $credential = New-Object System.Management.Automation.PSCredential ('dummyuser', $secureKey)
        $decryptedKey = $credential.GetNetworkCredential().Password

        $decryptedKey | Should -Be $mockApiKey
    }

    # Test Case 5: Test the -WhatIf parameter to ensure no changes are made.
    It 'Does NOT overwrite the file when -WhatIf is used' {
        # Create a dummy file with an old key that should not be changed.
        $oldKey = "do-not-overwrite-me"
        $secureOldKey = ConvertTo-SecureString -String $oldKey -AsPlainText -Force
        $secureOldKey | Export-CliXml -Path $keyFilePath

        # Run the function with -WhatIf. This causes ShouldProcess to return false.
        Set-VTApiKey -ApiKey $mockApiKey -WhatIf

        # The key in the file should still be the old, unchanged one.
        $secureKey = Import-CliXml -Path $keyFilePath
        $credential = New-Object System.Management.Automation.PSCredential ('dummyuser', $secureKey)
        $decryptedKey = $credential.GetNetworkCredential().Password

        $decryptedKey | Should -Be $oldKey
    }
}
