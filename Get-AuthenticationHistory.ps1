<#
.SYNOPSIS
    Track User Logon History in Active Directory Domain
    Get user authentication history in the domain based on successful user logon (authentication) events from the domain controller logs.
    Script will put this in a CSV file.
    
    Explanation of Logon Type Column:
    Logon Type 10 – Remote Interactive logon – a logon using RDP, shadow connection or Remote Assistance
    (this event may appear on a domain controller if an administrator or non-admin user having RDP access permission on DC logs on). 
    This event is used to monitor and analyze the activity of Remote Desktop Services users.
    
    Logon Type 3 –  Network logon (used when a user is authenticated on a DC and connects to a shared folder, printer or IIS service)
    

    Can be used to verify if and where a certain (service) AD account is still used.
     
.NOTES
    Version:        1.0
    Author:         Bart Tacken
    Creation Date:  21-04-2021
    Purpose/Change: Initial script
.PREREQUISITES
    Must be run on a domain controller.
    Enable two audit policies (Audit Logon and Audit Other Logon/Logoff Events).
    http://woshub.com/check-user-logon-history-active-directory-domain-powershell/
.EXAMPLE
    .\Get-AuthenticationHistory.ps1 -Account <Username, whose logon history you want to view> -DaysBackInHistory <User logon history for the last X days>
#>

Param(
    [Parameter(Mandatory=$True)]
    [String[]]$Account,
    
    [Parameter(Mandatory=$True)]
    [String]$DaysBackInHistory     
)
#---------------------------------------------------------[Initialisations]--------------------------------------------------------
[string]$DateStr = (Get-Date).ToString("s").Replace(":","-") # +"_" # Easy sortable date string   
$Array = @() # Create an empty array
$checkuser="*$Account*" # a username, whose logon history you want to view
$ExportCSV = ('C:\Beheer\AuthenticationLogging\' + $DateStr  + "_$Account" + "_$DaysBackInHistory" + '_Days' +'_NetworkAuthentication.csv')
 
Start-Transcript  ('c:\windows\temp\' + $DateStr  + '_NetworkAuthentication.log') -Force # Start logging
#-----------------------------------------------------------[Execution]------------------------------------------------------------    

# getting information about the user logon history for the last 2 days (you can change this value)
$startDate = (get-date).AddDays(-$DaysBackInHistory)
$DCs = Get-ADDomainController -Filter *
foreach ($DC in $DCs){
    $logonevents = Get-Eventlog -LogName Security -InstanceID 4624 -after $startDate -ComputerName $dc.HostName
    foreach ($event in $logonevents){
        if (($event.ReplacementStrings[5] -notlike '*$') -and ($event.ReplacementStrings[5] -like $checkuser)) {

            # Remote (Logon Type 10)
            if ($event.ReplacementStrings[8] -eq 10){
                $Array += New-Object -TypeName PSObject -Property @{ # Fill Array with custom objects
                    'Logon Type' = "Type 10: Remote Logon"
                    'Date' = $($event.TimeGenerated)
                    'User' = $($event.ReplacementStrings[5])
                    'Workstation' = $($event.ReplacementStrings[11])
                    'IP Address' = $($event.ReplacementStrings[18])
                    'DC' = $($dc.Name)
                } # End PS Object

                write-host "Type 10: Remote Logon`tDate: "$event.TimeGenerated "`tStatus: Success`tUser: "$event.ReplacementStrings[5] "`tWorkstation: "$event.ReplacementStrings[11] "`tIP Address: "$event.ReplacementStrings[18] "`tDC Name: " $dc.Name
            }
            # Network(Logon Type 3)
            if ($event.ReplacementStrings[8] -eq 3){
            $Array += New-Object -TypeName PSObject -Property @{ # Fill Array with custom objects
                'Logon Type' = "Type 3: Network Logon"
                'Date' = $($event.TimeGenerated)
                'User' = $($event.ReplacementStrings[5])
                'Workstation' = $($event.ReplacementStrings[11])
                'IP Address' = $($event.ReplacementStrings[18])
                'DC' = $($dc.Name)
            } # End PS Object              
                write-host "Type 3: Network Logon`tDate: "$event.TimeGenerated "`tStatus: Success`tUser: "$event.ReplacementStrings[5] "`tWorkstation: "$event.ReplacementStrings[11] "`tIP Address: "$event.ReplacementStrings[18] "`tDC Name: " $dc.Name
            }
        }
    }
}
$Array | Export-Csv -Path $ExportCSV -NoTypeInformation
Stop-Transcript
