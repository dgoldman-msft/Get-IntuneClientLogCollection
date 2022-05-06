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

        .PARAMETER EnableLogging
            Enable logging

        .EXAMPLE
            Get-IntuneClientLogCollection

            Will collect all of the Intune client side logs, event logs, registry information and compress them to a zip file

        .EXAMPLE
            Get-IntuneClientLogCollection -EnableLogging

            Will collect all of the Intune client side logs, event logs, registry information and compress them to a zip file for review as well as save logging of the script execution

        .EXAMPLE
            Get-IntuneClientLogCollection -Verbose

            Will run the script with verbose logging

        .EXAMPLE
            Get-IntuneClientLogCollection -LogFile "<DriveLetter>:\YourSaveLocation" -EnableLogging

            Will enable script execution logging and save to "<DriveLetter>:\YourSaveLocation"

        .NOTES
            $PSStyle code is for fix: https://github.com/PowerShell/PowerShell/pull/16811. Will be removed when backport is approved.
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
        $EnableLogging
    )

    begin {
        if ($PSVersionTable.PSEdition -eq 'Core') { $PSStyle.OutputRendering = 'Host' }
        if ($EnableLogging.IsPresent) { Start-Transcript -Path $LogFile }
    }

    process {
        $currentWinPrincipal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
        if (-NOT ($CurrentWinPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))) {
            Write-Warning "Insufficient permissions to run this script. Open the PowerShell console as an administrator and run this script again."
            return
        }
        else {
            Write-Output "Running with elevated permissions. Starting data collection"
        }

        $directories = @($OutputDirectory, $TempDirectory)
        foreach ($directory in $directories) {
            if (-NOT (Test-Path -Path $directory -ErrorAction Stop)) {
                Write-Verbose "$($directory) not found! Creating directory"
                try {
                    $null = New-Item -Path $directory -ItemType Directory -ErrorAction Stop
                }
                catch {
                    $_.Exception.Message
                    return
                }
            }
            else {
                Write-Verbose -Message "$directory already exists"
            }
        }

        # Set the location so we can remove the files
        Set-Location $OutputDirectory
        try {
            Write-Verbose -Message "Retrieving Directory Registray Service Information"
            $dsregcmd = New-Object PSObject
            Dsregcmd /status | Where-Object { $_ -match ' : ' } | ForEach-Object {
                $item = $_.Trim() -split '\s:\s'
                $dsregcmd | Add-Member -MemberType NoteProperty -Name $($Item[0] -replace '[:\s]', '') -Value $item[1] -ErrorAction SilentlyContinue }
            $dsregcmd | Out-File -FilePath $OutputDirectory\Dsregcmd.txt -ErrorAction SilentlyContinue

            Compress-Archive -Path $OutputDirectory\Dsregcmd.txt -DestinationPath $OutputDirectory\Dsregcmd.zip -CompressionLevel "Fastest" -Update -ErrorAction SilentlyContinue
            Write-Verbose -Message "Compressing Directory Registray Service Information to $OutputDirectory\Dsregcmd.zip"
        }
        catch {
            Write-Output "Error: $_"
        }

        $inTuneDirectories = @( @("C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\*", "IntuneManagementExtensionLogs.zip"),
            @("C:\Program files (x86)\Microsoft Intune Management Extension\Policies\Scripts\*", "IntuneScriptLogs.zip"),
            @("C:\Program files (x86)\Microsoft Intune Management Extension\Policies\Results\*", "IntuneScriptResultLogs.zip"))

        $sccmDirectories = @( @("$env:windir\ccm\logs*\*", "CCMLogs.zip"),
            @("$env:windir\ccmsetup\logs*\ccmsetup*", "CCMSetupLogs.zip"))

        try {
            # Backup registry and dsregcmd information for script executions
            Write-Verbose -Message "Retrieving Windows Device Management Registry Information"
            Get-ChildItem HKLM:\Software\Microsoft\IntuneManagementExtension\Policies\ -Recurse -ErrorAction SilentlyContinue | Out-File -FilePath $OutputDirectory\Registry.txt -ErrorAction SilentlyContinue
            Compress-Archive -Path $OutputDirectory\Registry.txt -DestinationPath $OutputDirectory\RegistryLogs.zip -CompressionLevel "Fastest" -Update -ErrorAction SilentlyContinue
            Write-Verbose -Message "Creating compress archive for Windows Device Management Registry Information to $OutputDirectory\Registry.zip"
        }
        catch {
            Write-Output "Error: $_"
            return
        }

        try {
            # Backup windows event logs
            Write-Verbose -Message "Retrieving Windows Device Management Event Logs"
            Get-WinEvent -LogName Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational -ErrorAction SilentlyContinue | Export-Csv $OutputDirectory\Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider-Operational.csv -NoTypeInformation -ErrorAction Stop
            Get-WinEvent -LogName Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin -ErrorAction SilentlyContinue | Export-Csv $OutputDirectory\Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider-Admin.csv -NoTypeInformation -ErrorAction Stop
            Compress-Archive -Path $OutputDirectory\*.csv -DestinationPath $OutputDirectory\DeviceManagementEventLogs.zip -CompressionLevel "Fastest" -Update -ErrorAction Stop
            Write-Verbose -Message "Creating compress archive for Windows Device Management Event Logs to $OutputDirectory\DeviceManagementEventLogs.zip"
        }
        catch {
            Write-Output "Error: $_"
            return
        }

        foreach ($ccmDir in $sccmDirectories) {
            try {
                if ($ccmDir.contains("\ccm")) { Write-Verbose -Message "Checking for Configuration Management Extension files" }
                if ($ccmDir.contains("\ccmsetup")) { Write-Verbose -Message "Checking for Configuration Management Setup files" }

                if (Get-ChildItem -Path $($ccmDir[0]) -Filter "*.*" -ErrorAction SilentlyContinue) {
                    Write-Verbose -Message "Configuration Management Extension files found. Making a backup copy of items from: $($($ccmDir[0]).Substring(0, $ccmDir[0].length-1))"

                    if (Copy-Item -Path $($ccmDir[0]) -Destination $TempDirectory -Force -Recurse -PassThru -ErrorAction SilentlyContinue) {
                        Write-Verbose -Message "Copy of $($ccmDir[0]) to $($TempDirectory) successful!"
                    }

                    Write-Verbose -Message "Attemping to compress $($ccmDir[0])"
                    Compress-Archive -Path $TempDirectory\*.* -DestinationPath (Join-Path -Path $OutputDirectory -ChildPath $($ccmDir[1])) -CompressionLevel "Fastest" -Update -ErrorAction Stop
                    Write-Verbose "$($ccmDir[1]) sucessfully compressed and saved archive to $OutputDirectory"

                    # Remove the files for each directory to prep for the next archive
                    Write-Verbose "Cleaning up temp files from $TempDirectory"
                    Remove-Item -Path $TempDirectory\*.* -Force -Recurse -ErrorAction SilentlyContinue
                }
                else {
                    Write-Verbose -Message "No files found in $($($ccmDir[0]).Substring(0, $ccmDir[0].length-1))"
                }
            }
            catch {
                Write-Output "Error: $_"
            }
        }

        foreach ($intuneDir in $inTuneDirectories) {
            try {
                if ($intuneDir.contains("\IntuneManagementExtension")) { Write-Verbose -Message "Checking for Intune Management Extension files" }
                if ($intuneDir.contains("\Scripts")) { Write-Verbose -Message "Checking for Intune Management Extension PowerShell script executions" }
                if ($intuneDir.contains("\Results\")) { Write-Verbose -Message "Checking for Intune Management Extension PowerShell script execution results" }

                if (Get-ChildItem -Path $($intuneDir[0]) -Filter "*.*" -ErrorAction SilentlyContinue) {
                    Write-Verbose -Message "Intune Management Extension files found. Making a backup copy of items from: $($($intuneDir[0]).Substring(0, $intuneDir[0].length-1))"

                    if (Copy-Item -Path $($intuneDir[0]) -Destination $TempDirectory -Force -Recurse -PassThru -ErrorAction SilentlyContinue) {
                        Write-Verbose -Message "Copy of $($intuneDir[0]) to $($TempDirectory) successful!"
                    }

                    Write-Verbose -Message "Attemping to compress $($intuneDir[0])"
                    Compress-Archive -Path $TempDirectory\*.* -DestinationPath (Join-Path -Path $OutputDirectory -ChildPath $($intuneDir[1])) -CompressionLevel "Fastest" -Update -ErrorAction Stop
                    Write-Verbose "$($intuneDir[1]) sucessfully compressed and saved archive to $OutputDirectory"

                    # Remove the files for each directory to prep for the next archive
                    Write-Verbose "Cleaning up temp files from $TempDirectory"
                    Remove-Item -Path $TempDirectory\*.* -Force -Recurse -ErrorAction SilentlyContinue
                }
                else {
                    Write-Verbose -Message "No files found in $($($intuneDir[0]).Substring(0, $intuneDir[0].length-1))"
                }
            }
            catch {
                Write-Output "Error: $_"
                return
            }
        }

        try {
            # Compress all needed archives in to one archive
            Write-Verbose "Compressing entire collection into $($OutputDirectory)\IntuneLogCollection.zip"
            $compressionCollection = @{
                Path             = "$OutputDirectory\DeviceManagementEventLogs.zip", "$OutputDirectory\IntuneManagementExtensionLogs.zip", "$OutputDirectory\RegistryLogs.zip", "$OutputDirectory\Dsregcmd.zip", "CCMLogs.zip", "CCMSetupLogs.zip"
                CompressionLevel = "Fastest"
                DestinationPath  = "$OutputDirectory\IntuneLogCollection.zip"
            }
            Compress-Archive @compressionCollection -Update -ErrorAction Stop
        }
        catch {
            Write-Output "Error: $_"
            return
        }

        try {
            # Cleanup
            Write-Verbose "Starting cleanup."
            Remove-Item -Path $TempDirectory -Force -Recurse -ErrorAction Stop
            Write-Verbose "Removed $($TempDirectory) and all temp items"
            Remove-Item -Path $OutputDirectory\Registry.txt -Force -ErrorAction Stop
            Write-Verbose "Removed $OutputDirectory\Registry.txt"
            Get-ChildItem -Path $OutputDirectory -ErrorAction Stop | Foreach-Object {
                if ($_.Name -ne 'IntuneLogCollection.zip' -and $_.Name -ne 'CollectionTranscript.txt') {
                    Remove-Item $_ -Force
                    Write-Verbose "Removed $_"
                }
            }
        }
        catch {
            Write-Output "Error: $_"
        }
    }

    end {
        if ($PSVersionTable.PSEdition -eq 'Core') { $PSStyle.OutputRendering = 'Ansi' }
        if ($EnableLogging.IsPresent) { Stop-Transcript }
        Write-Output "Data collection completed!"
    }
}