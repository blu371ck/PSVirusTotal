$ModulePath = Split-Path -Parent $PSCommandPath

Get-ChildItem -Path "$ModulePath\Public" -Filter "*.ps1" | ForEach-Object {
    . $_.FullName
}

Get-ChildItem -Path "$ModulePath\Private" -Filter "*.ps1" | ForEach-Object {
    . $_.FullName
}