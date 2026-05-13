# Splunk Detection Queries

## Failed Logons (EventCode 4625)

```spl
index=main source="WMI:WinEventLog:Security" EventCode=4625
| stats count by Account_Name
| sort - count
```

Purpose:
Detect failed authentication attempts by account.

---

## Successful Logons (EventCode 4624)

```spl
index=main source="WMI:WinEventLog:Security" EventCode=4624
| stats count by Account_Name
| sort - count
```

Purpose:
Monitor successful authentication events.

---

## Authentication Event Summary

```spl
index=main source="WMI:WinEventLog:Security" (EventCode=4624 OR EventCode=4625)
| stats count by EventCode
```

Purpose:
Compare successful vs failed authentication activity.

---

## Service Installation Monitoring (EventCode 7045)

```spl
index=main source="WMI:WinEventLog:System" EventCode=7045
| table _time host Service_Name Service_File_Name Service_Account
| sort - _time
```

Purpose:
Detect newly installed Windows services.

---

## Process Creation Monitoring (EventCode 4688)

```spl
index=main source="WMI:WinEventLog:Security" EventCode=4688
| stats count by New_Process_Name
| sort - count
```

Purpose:
Monitor newly created processes.

---

## PowerShell Monitoring

```spl
index=main source="WMI:WinEventLog:Security" EventCode=4688
| search New_Process_Name="*powershell*"
| table _time host Account_Name New_Process_Name Process_Command_Line
| sort - _time
```

Purpose:
Identify PowerShell execution activity for security monitoring and threat hunting.
