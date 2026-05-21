
 +---------------------------------------------------------------------------+
 |                                                                           |
 |       L o g S e n t i n e l A I   —   Security Agent  v1.2              |
 |                                                                           |
 |       AI-Powered Intrusion Detection  |  Real-Time Threat Monitoring     |
 |                                                                           |
 +---------------------------------------------------------------------------+

  Platform   :  Windows 10 / 11 (64-bit)
  Python     :  Not required — the EXE includes everything
  Connection :  Internet access required

  Dashboard  :  https://log-sentinel-ai-h3bmh3hbh6e3c6bx.francecentral-01.azurewebsites.net


 ┌─ QUICK START ─────────────────────────────────────────────────────────────┐
 │                                                                           │
 │   1.  Double-click  LogSentinelAI.exe                                    │
 │   2.  Click "Yes" when Windows asks for Administrator permission          │
 │   3.  A pairing code appears in the console window                        │
 │   4.  Sign in to your dashboard and click  Connect Machine                │
 │   5.  Enter the 6-character code — your machine is now monitored          │
 │                                                                           │
 │   Your dashboard opens automatically in your browser.                     │
 │                                                                           │
 └───────────────────────────────────────────────────────────────────────────┘


 WHAT DOES IT DO?
 ----------------
 LogSentinelAI monitors your Windows Event Logs (Security, System, Application,
 PowerShell) for signs of intrusion, privilege escalation, brute-force attacks,
 and other threats. Detected events are scored by an AI model and displayed on
 your personal security dashboard in real time.

 You receive email and browser notifications for high-severity alerts.


 FILES IN THIS FOLDER
 --------------------
   LogSentinelAI.exe   Main agent — double-click to start. No Python needed.
   START.bat           Python fallback — use if the EXE does not work on your PC.
   UNINSTALL.bat       Removes the agent from Windows startup.
   agent.py            Agent source code (used internally by both the EXE and START.bat).
   requirements.txt    Python package list (only needed for START.bat mode).
   README.txt          This file.


 PAIRING YOUR MACHINE
 --------------------
 Every time the agent starts, it generates a unique 6-character code:

   +------------------------------------------------+
   |  MACHINE PAIRING CODE                          |
   |                                                |
   |  Code:    A3X7KP                               |
   |  Machine: your-pc                              |
   +------------------------------------------------+
     1. Go to the dashboard
     2. Click  Connect Machine
     3. Enter the code shown above
     (code expires in 10 minutes)

 Once paired, your machine appears on the dashboard with ONLINE status,
 real-time health metrics (CPU, RAM, Disk), and a full alert history.

 NOTE: If the server is temporarily unreachable, the agent retries the
 pairing registration every 5 minutes — no need to restart the EXE.


 AUTO-START WITH WINDOWS
 -----------------------
 The first time you run the EXE you will be asked:
   "Would you like Log Sentinel AI to start automatically when Windows starts?"

 Clicking YES means your machine is protected from the moment Windows boots —
 no manual action required.

 To disable auto-start later:
   • Run  UNINSTALL.bat  (included in this folder), OR
   • Windows Settings -> Apps -> Startup -> LogSentinelAI -> Off, OR
   • Run  LogSentinelAI.exe --uninstall  from a command prompt


 STOPPING THE AGENT
 ------------------
 Press  Ctrl+C  in the agent window, or close the console.
 The EXE automatically restarts the agent if it exits unexpectedly.


 TROUBLESHOOTING
 ---------------
 Problem: EXE closes immediately after opening
   Solution: Right-click -> "Run as administrator"
             Administrator rights are required to read Security event logs.

 Problem: Machine shows OFFLINE on the dashboard
   Solution: Make sure LogSentinelAI.exe is still running in the background.
             Status updates every 10 seconds — check again after 15 seconds.
             Verify you have an active internet connection.

 Problem: Pairing code does not work
   Solution: Codes expire after 10 minutes.
             Wait up to 5 minutes — the EXE retries pairing automatically.
             Or close and re-run the EXE to get a fresh code instantly.

 Problem: No email alerts received
   Solution: Ask your administrator to verify your account email address.
             Check your spam / junk mail folder.

 Problem: Antivirus flags the EXE
   Solution: This is a false positive — the EXE reads Windows Event Logs and
             opens network connections, which some AV heuristics flag.
             Add LogSentinelAI.exe to your antivirus exclusions list.

 Problem: EXE keeps restarting in a loop
   Solution: This is normal recovery behaviour — the EXE auto-recovers from
             crashes. If the loop is immediate, check your internet connection.


 SYSTEM REQUIREMENTS
 -------------------
   Operating System  :  Windows 10 (version 1903+) or Windows 11
   Architecture      :  64-bit only
   Internet          :  Required — the agent uploads logs to the cloud
   Admin Rights      :  Required to read Windows Security event logs
   Python            :  NOT required for the EXE
                        Python 3.8+ required only for START.bat mode

 MONITORED EVENT CHANNELS
 -------------------------
   Security          Authentication, privilege escalation, user management
   System            Service changes, driver installs, crash reports
   Application       App errors, unexpected terminations
   PowerShell        Script execution, pipeline logging


 +---------------------------------------------------------------------------+
 |   Dashboard : https://log-sentinel-ai-h3bmh3hbh6e3c6bx.francecentral-01.azurewebsites.net
 |   Support   : Contact your LogSentinelAI administrator
 +---------------------------------------------------------------------------+
