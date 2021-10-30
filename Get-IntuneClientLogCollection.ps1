function Get-IntuneClientLogCollection {
    <#
        .SYNOPSIS
            Collect all Intune client side logs

        .DESCRIPTION
            Collect all Intune client side logs, event logs, registry information and compress them to a zip file

        .PARAMETER OutputDirectory
            Save location for the data collection

        .PARAMETER TempDirectory
            Temp copy location for in use files so they can be archived

        .PARAMETER LogFile
            Output logging file

        .PARAMETER Logging
            Enable logging

        .EXAMPLE
            Get-IntuneClientLogCollection

            Will collect all of the Intune client side logs, event logs, registry information and compress them to a zip file

        .EXAMPLE
            Get-IntuneClientLogCollection -Logging

            Will collect all of the Intune client side logs, event logs, registry information and compress them to a zip file for review as well as save logging of the script execution

        .EXAMPLE
            Get-IntuneClientLogCollection -LogFile "<DriveLetter>:\YourSaveLocation"

            Will enable script execution logging

        .NOTES
            None
    #>

    [cmdletbinding()]
    param(
        [string]
        $OutputDirectory = "c:\IntuneClientLogs",

        [string]
        $TempDirectory = "c:\IntuneClientLogs\Temp",

        [string]
        $LogFile = "C:\IntuneClientLogs\CollectionTranscript.txt",

        [switch]
        $Logging
    )

    begin {
        Write-Verbose "Saving `$ErrorActionPreference which is current set to $ErrorActionPreference and changing to Stop"
        $ErrorActionPreferenceOld = $ErrorActionPreference
        $ErrorActionPreference = "Stop"
        if ($Logging.IsPresent) { Start-Transcript -Path $LogFile }
        Write-Output "Starting data collection"
    }

    process {
        $directories = @($OutputDirectory, $TempDirectory)
        foreach ($directory in $directories) {
            if (-NOT (Test-Path -Path $directory)) {
                Write-Verbose "Directory not found! Creating directory: $directory"
                try {
                    $null = New-Item -Path $directory -ItemType Directory
                }
                catch {
                    $_.Exception.Message
                    return
                }
            }
            else {
                Write-Verbose -Message "Directory: $directory already exists"
            }
        }

        try {
            $inTuneDirectories = @( @("C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\*", "IntuneManagementExtensionLogs.zip"),
                @("C:\Program files (x86)\Microsoft Intune Management Extension\Policies\Scripts\*", "IntuneScriptLogs.zip"),
                @("C:\Program files (x86)\Microsoft Intune Management Extension\Policies\Results\*", "IntuneScriptResultLogs.zip")
            )

            # Backup registry information for script executions
            try {
                Write-Verbose -Message "Retrieving Windows Device Management Registry Information"
                Get-ChildItem HKLM:\Software\Microsoft\IntuneManagementExtension\Policies\ -Recurse | Out-File -FilePath $OutputDirectory\Registry.txt
                Compress-Archive -Path $OutputDirectory\Registry.txt -DestinationPath $OutputDirectory\RegistryLogs.zip -CompressionLevel "Fastest" -Update
                Write-Verbose -Message "Compressing Windows Device Management Registry Information to $OutputDirectory\Registry.zip"
            }
            catch {
                Write-Output "$_.Exception.Message"
                return
            }

            # Backup windows event logs
            try {
                Write-Verbose -Message "Retrieving Windows Device Management Event Logs"
                Get-WinEvent -LogName Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational | Export-Csv $OutputDirectory\Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider-Operational.csv -NoTypeInformation
                Get-WinEvent -LogName Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin | Export-Csv $OutputDirectory\Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider-Admin.csv -NoTypeInformation
                Compress-Archive -Path $OutputDirectory\*.csv -DestinationPath $OutputDirectory\DeviceManagementEventLogs.zip -CompressionLevel "Fastest" -Update
                Write-Verbose -Message "Compressing Windows Device Management Event Logs to $OutputDirectory\DeviceManagementEventLogs.zip"
            }
            catch {
                Write-Output "$_.Exception.Message"
                return
            }

            foreach ($intuneDir in $inTuneDirectories) {
                try {
                    if ($intuneDir.contains("\IntuneManagementExtension")) { Write-Verbose -Message "Checking for Intune Management Extension files" }
                    if ($intuneDir.contains("\Scripts")) { Write-Verbose -Message "Checking for Intune Management Extension PowerShell script executions" }
                    if ($intuneDir.contains("\Results\")) { Write-Verbose -Message "Checking for Intune Management Extension PowerShell script execution results" }

                    if (Get-ChildItem -Path $($intuneDir[0]) -Filter "*.*") {
                        Write-Verbose -Message "Intune Management Extension files found. Making a backup copy of items from: $($($intuneDir[0]).Substring(0, $intuneDir[0].length-1))"

                        if (Copy-Item -Path $($intuneDir[0]) -Destination $TempDirectory -Force -Recurse -PassThru) {
                            Write-Verbose -Message "Copy of $($intuneDir[0]) to $($TempDirectory) successful!"
                        }

                        Write-Verbose -Message "Attemping to compress $($intuneDir[0])"
                        Compress-Archive -Path $TempDirectory\*.* -DestinationPath (Join-Path -Path $OutputDirectory -ChildPath $($intuneDir[1])) -CompressionLevel "Fastest" -Update
                        Write-Verbose "$($intuneDir[1]) sucessfully zipped and saved to $OutputDirectory"

                        # Remove the files for each directory to prep for the next archive
                        Write-Verbose "Cleaning up temp files from $TempDirectory"
                        Remove-Item -Path $TempDirectory\*.* -Force -Recurse
                    }
                    else {
                        Write-Verbose -Message "No files found in $($($intuneDir[0]).Substring(0, $intuneDir[0].length-1))"
                    }
                }
                catch {
                    Write-Output "$_.Exception.Message"
                    return
                }
            }

            # Compress all needed archives in to one archive
            try {
                Write-Verbose "Compressing entire collection into $($OutputDirectory)\IntuneLogCollection.zip"
                $compressionCollection = @{
                    Path = "$OutputDirectory\DeviceManagementEventLogs.zip", "$OutputDirectory\IntuneManagementExtensionLogs.zip", "$OutputDirectory\RegistryLogs.zip"
                    CompressionLevel = "Fastest"
                    DestinationPath = "$OutputDirectory\IntuneLogCollection.zip"
                }
                Compress-Archive @compressionCollection -Update
            }
            catch {
                Write-Output "$_.Exception.Message"
                return
            }

            # Cleanup
            try {
                Write-Verbose "Starting cleanup. Removing $TempDirectory and all temp items"
                Remove-Item -Path $TempDirectory -Force -Recurse
                Remove-Item -Path $OutputDirectory\Registry.txt -Force
                Get-ChildItem -Path $OutputDirectory | foreach-object { 
                    if ($_.Name -ne "IntuneLogCollection.zip") { Remove-Item $_ -Force }
                }
            }
            catch { Write-Output "$_.Exception.Message" }
        }
        catch {
            Write-Output "$_.Exception.Message"
            return
        }
    }

    end {
        

        if ($Logging.IsPresent) { Stop-Transcript }
        $ErrorActionPreference = $ErrorActionPreferenceOld
        Write-Verbose "Restored `$ErrorActionPreference back to $ErrorActionPreference"
        Write-Output "Data collection completed!"
    }
}