# Get-IntuneClientLogCollection

Collect all Intune client side logs, event logs, registry information and compress them to a zip file

> WARNING: This data collection can contain sensitive information such as computer names, file names, and other PII / OII. Please vet files before sending to any support professionals for review!

> <span style="color:red">NOTICE</span>: <span style="color:yellow"> When you run this script you acknowledge that you take full responsibility for the data collection and security of your private information!</span>

- EXAMPLES
  
> Get-IntuneClientLogCollection

    Will collect all of the Intune client side logs, event logs, registry information and compress them to a zip file

> Get-IntuneClientLogCollection -Logging

    Will collect all of the Intune client side logs, event logs, registry information and compress them to a zip file for review as well as save logging of the script execution

> Get-IntuneClientLogCollection -LogFile "DriveLetter:\YourSaveLocation"

    Enable transcript logging