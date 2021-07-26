<#
.SYNOPSIS
    Get Domain User Logon History Based on Kerberos Events.
    Get user authentication history in the domain based on the event of a Kerberos ticket issue (TGT Request — EventID 4768). 
    Script will put this in a CSV file (network logons are excluded, as well as access events to the DC folders during getting GPO files or running logon scripts)

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
    .\Get-KerberosAuthentication.ps1 -Account <Username, whose logon history you want to view> -DaysBackInHistory <User logon history for the last X days>
#>
Param(
    [Parameter(Mandatory=$True)]
    [String]$DaysBackInHistory     
)
#---------------------------------------------------------[Initialisations]--------------------------------------------------------
[string]$DateStr = (Get-Date).ToString("s").Replace(":","-") # +"_" # Easy sortable date string   
$alluserhistory = @() # Create an empty array
$ExportCSV = ('C:\Beheer\AuthenticationLogging\' + $DateStr  + "_$Account" + "_$DaysBackInHistory" + '_Days' +'_KerberosAuthentication.csv')
$startDate = (get-date).AddDays(-$DaysBackInHistory)
$DCs = Get-ADDomainController -Filter *
Start-Transcript  ('c:\windows\temp\' + $DateStr  + '_KerberosAuthentication.log') -Force # Start logging
#-----------------------------------------------------------[Execution]------------------------------------------------------------ 

foreach ($DC in $DCs){
    $logonevents = Get-Eventlog -LogName Security -InstanceID 4768 -after $startDate -ComputerName $dc.HostName
    foreach ($event in $logonevents){
        if ($event.ReplacementStrings[0] -notlike '*$') {
            $userhistory = New-Object PSObject -Property @{
            UserName = $event.ReplacementStrings[0]
            IPAddress = $event.ReplacementStrings[9]
            Date = $event.TimeGenerated
            DC = $dc.Name
        }
        $alluserhistory += $userhistory
        }
    }
}
$alluserhistory | Export-Csv -Path $ExportCSV -NoTypeInformation
Stop-Transcript
