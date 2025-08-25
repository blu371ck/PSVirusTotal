# PSVirusTotal
PowerShell script that interacts with VirusTotal APIs.

Work in progress!

## Command Reference
### `Set-VTApiKey`
This function securely saves or overwrites your VirusTotal API key for future use by other scripts.

### Syntax
```
Set-VTApiKey -ApiKey <ApiKey> [-Force]
```

### Parameters
- `-ApiKey` <String> (Required)
Your personal VirusTotal API key.
- `-Force` <Switch> (Optional)
Overwrites the existing API key file without prompting for confirmation.

### Usage Examples
1. Set the API key for the first time
```PowerShell
Set-ApiKey -ApiKey 'your_long_api_key_here'
```
This command securely saves your API key. If a key already exists, it will prompt for confirmation before overwriting.

2. Overwrite an existing key without a prompt
```PowerShell
Set-ApiKey -ApiKey 'a_new_api_key' -Force
```
_This command uses the -Force switch to immediately overwrite any previously saved API key._

---
### `Get-IpAddressReport`
Retrieves a comprehensive report for a given IP address from the VirusTotal API.

### Syntax
```
Get-VTIpAddressReport -IpAddress <IPAddress> [-OutFile <String>]
```

### Parameters
- `-IpAddress` (Required)
The IP address you want to query. The function validates that the input is a correctly formatted IP address.
- `-OutFile` (Optional)
Specifies a file path where the report should be saved. If provided, the full JSON report will be written to this file. If omitted, the report object will be displayed in the console.

### Usage Examples
1. Displaying a report in the console
This command retrieves the report for the IP address 8.8.8.8 and displays the results as a PowerShell object in the terminal.
```powershell
Get-IpAddressReport -IpAddress 8.8.8.8
```
2. Saving a report to a JSON file
This command retrieves the report for the IP address 1.1.1.1 and saves it as a formatted JSON file in the C:\Reports directory.
```powershell
Get-IpAddressReport -IpAddress 1.1.1.1 -OutFile "C:\Reports\cloudflare_dns_report.json"
```

---
### `Get-IpAddressComments`
Retrieves the latest community comments for a given IP address from the VirusTotal API.

### Syntax
```
Get-IpAddressComments -IpAddress <IPAddress> [-Limit <Int32>] [-OutFile <String>]
```

### Parameters
- `-IpAddress` (Required)
The IP address for which you want to retrieve comments.
- `-Limit` (Optional)
The maximum number of comments to retrieve.
Default value: 10
- `-OutFile` (Optional)
Specifies a file path where the comments should be saved. If provided, the full JSON response will be written to this file. If omitted, the response will be displayed in the console.

### Examples
1. Get the 10 most recent comments
This command retrieves the 10 most recent comments for the IP address 8.8.8.8 and displays them as a formatted JSON string in the terminal.
```powershell
Get-IpAddressComments -IpAddress 8.8.8.8
```
2. Get the 5 most recent comments
This command retrieves the 5 most recent comments for the IP address 1.1.1.1.
```powershell
Get-IpAddressComments -IpAddress 1.1.1.1 -Limit 5
```
3. Save comments to a JSON file
This command retrieves the default number of comments for the IP address 8.8.4.4 and saves the results to a file named google_dns_comments.json.
```powershell
Get-IpAddressComments -IpAddress 8.8.4.4 -OutFile "C:\Reports\google_dns_comments.json"
```

----
### `Get-IpAddressObjects`
Retrieves objects related to a given IP address from the VirusTotal API, such as resolutions, communicating files, or URLs. This command automatically handles API pagination to retrieve all available results.

### Syntax
```
Get-IpAddressObjects -IpAddress <IPAddress> -Relationship <String> [-Limit <Int32>] [-OutFile <String>]
```
### Parameters
- `-IpAddress` (Required)
The IP address for which you want to retrieve related objects.
- `-Relationship` (Required)
The type of relationship to query. You can press the Tab key after this parameter in your terminal to cycle through all valid options.
Valid Options: communicating_files, downloaded_files, graphs, historical_whois, historical_ssl_certificates, referrer_files, resolutions, urls, user_votes.
- `-Limit` (Optional)
The number of results to retrieve per API request. The function will still loop through all pages to get every result, but this controls the size of each chunk.
Default value: 10
- `-OutFile` (Optional)
Specifies a file path where the results should be saved. If provided, the full JSON response will be written to this file. If omitted, the results are returned as PowerShell objects to the console.

### Examples
1. Get all DNS resolutions for an IP
This command retrieves all historical DNS resolutions for the IP address 8.8.8.8 and displays them in the console.
```powershell
Get-IpAddressObjects -IpAddress 8.8.8.8 -Relationship resolutions
```
2. Get all URLs associated with an IP and save to a file
This command retrieves all URLs known to be associated with the IP address 34.98.99.30 and saves the complete results to a JSON file.
```powershell
Get-IpAddressObjects -IpAddress 34.98.99.30 -Relationship urls -OutFile "C:\Reports\related_urls.json"
```

---
### `Get-IpAddressObjectDescriptors`
Retrieves object descriptors related to a given IP address from the VirusTotal API, such as resolutions, communicating files, or URLs. This command automatically handles API pagination to retrieve all available results.

### Syntax
```
Get-IpAddressObjects -IpAddress <IPAddress> -Relationship <String> [-Limit <Int32>] [-OutFile <String>]
```
### Parameters
- `-IpAddress` (Required)
The IP address for which you want to retrieve related objects.
- `-Relationship` (Required)
The type of relationship to query. You can press the Tab key after this parameter in your terminal to cycle through all valid options.
Valid Options: communicating_files, downloaded_files, graphs, historical_whois, historical_ssl_certificates, referrer_files, resolutions, urls, user_votes.
- `-Limit` (Optional)
The number of results to retrieve per API request. The function will still loop through all pages to get every result, but this controls the size of each chunk.
Default value: 10
- `-OutFile` (Optional)
Specifies a file path where the results should be saved. If provided, the full JSON response will be written to this file. If omitted, the results are returned as PowerShell objects to the console.

### Examples
1. Get all DNS resolutions for an IP
This command retrieves all historical DNS resolution descriptors for the IP address 8.8.8.8 and displays them in the console.
```powershell
Get-IpAddressObjectDescriptors -IpAddress 8.8.8.8 -Relationship resolutions
```
2. Get all URLs associated with an IP and save to a file
This command retrieves all URL descriptors known to be associated with the IP address 34.98.99.30 and saves the complete results to a JSON file.
```powershell
Get-IpAddressObjectDescriptors -IpAddress 34.98.99.30 -Relationship urls -OutFile "C:\Reports\related_urls.json"
```