# Failed Logons (4625)
index=main source="WMI:WinEventLog:Security" EventCode=4625
| stats count by Account_Name
| sort - count

Purpose:
Detect failed authentication attempts by account name.

--------------------------------------------------

# Successful Logons (4624)
index=main source="WMI:WinEventLog:Security" EventCode=4624
| stats count by Account_Name
| sort - count

Purpose:
Monitor successful Windows authentication events.

--------------------------------------------------

# Authentication Summary
index=main source="WMI:WinEventLog:Security" (EventCode=4624 OR EventCode=4625)
| stats count by EventCode

Purpose:
Compare successful and failed authentication activity.

--------------------------------------------------

# Service Installation Events (7045)
index=main source="WMI:WinEventLog:System" EventCode=7045
| table _time host Service_Name Service_File_Name Service_Account
| sort - _time

Purpose:
Detect newly installed Windows services.

--------------------------------------------------

# Process Creation Monitoring (4688)
index=main source="WMI:WinEventLog:Security" EventCode=4688
| stats count by New_Process_Name
| sort - count

Purpose:
Monitor newly created processes.

--------------------------------------------------

# PowerShell Monitoring
index=main source="WMI:WinEventLog:Security" EventCode=4688
| search New_Process_Name="*powershell*"
| table _time host Account_Name New_Process_Name Process_Command_Line
| sort - _time

Purpose:
Identify PowerShell execution activity for threat hunting and detection monitoring.
