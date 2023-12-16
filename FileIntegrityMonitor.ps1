# path to files been monitored
$path = Get-ChildItem -Path .\files

Write-Host ""
Write-Host "Hello, What would you like to do?"
Write-Host ""
Write-Host "    A) Calculate new Hash value and store in PreviousHash?"
Write-Host "    B) Begin monitoring files with saved Baseline?"
Write-Host ""
$response = Read-Host -Prompt "Please enter 'A' or 'B'"
Write-Host ""


# calculate the file hash in the given path
function Get-FileHashValue () {
    param (
        $FilePath,
        $Algorithm = "SHA512"
    )

    if (Test-Path $FilePath) {
        try {
            $fileHash = Get-FileHash -Path $FilePath -Algorithm $Algorithm
            Write-Host "The hash has been successfully generated"
            return $fileHash
        } catch {
            Write-Host "Error calculating hash value: $_.Exception.Message"
        }
    } else {
        Write-Host "File not found at the specified path."
    }
}

Function Erase-PreviousHashValue-If-Exists() {
    $hashExists = Test-Path -Path .\previousHashValue.txt

    if ($hashExists) {
        # Delete previousHashValue.txt file if it exits
        Remove-Item -Path .\previousHashValue.txt
    }
}

# Define the behavior based on user response
if ($response -eq "A".ToUpper()) {
    # Delete previousHash.txt if it already exists
    Erase-PreviousHashValue-If-Exists

    # Calculate Hash from the target files and store in previousHash.txt
    # Collect all files in the target folder
    $files = Get-ChildItem -Path .\files

    # For each file, calculate the hash, and write to baseline.txt
    foreach ($file in $files) {
        $hash = Get-FileHashValue $file.FullName
        "$($hash.Path)|$($hash.Hash)" | Out-File -FilePath .\previousHashValue.txt -Append
    }
    
}

elseif ($response -eq "B".ToUpper()) {
    # Initialize a dictionary to store file hashes from the previousHashValue
    $fileHashDictionary = @{}

    # Load file paths and hashes from baseline.txt into the dictionary
    $filePathsAndHashes = Get-Content -Path .\previousHashValue.txt
    
    foreach ($fileData in $filePathsAndHashes) {
        # Split each line by "|" delimiter to separate file path and hash, then add to the dictionary
        $filePath, $fileHash = $fileData.Split("|")
        $fileHashDictionary.Add($filePath, $fileHash)
    }

    # Continuously monitor files against the previousHashValue
    while ($true) {
        Start-Sleep -Seconds 2  # Pause for 2 second
        
        # Retrieve files in the specified directory
        $files = Get-ChildItem -Path .\files

        # Check each file's hash against the baseline and detect changes
        foreach ($file in $files) {
            $hash = Calculate-File-Hash $file.FullName

            # Notify if a new file has been created
            if (-not $fileHashDictionary.ContainsKey($hash.Path)) {
                Write-Host "New file created: $($hash.Path)" -ForegroundColor Green
            }
            else {
                # Notify if a file has been changed
                if ($fileHashDictionary[$hash.Path] -ne $hash.Hash) {
                    Write-Host "File modified: $($hash.Path)" -ForegroundColor Yellow
                }
            }
        }

        # Check for deleted files from the baseFolder
        foreach ($key in $fileHashDictionary.Keys) {
            $baselineFileExists = Test-Path -Path $key
            if (-not $baselineFileExists) {
                Write-Host "File deleted: $key" -ForegroundColor DarkRed -BackgroundColor Gray
            }
        }
    }
}
