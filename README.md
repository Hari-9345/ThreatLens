\# ThreatLens

\## Windows Endpoint Monitoring \& Explainable Threat Detection



\### 1. Project Overview

ThreatLens is an experimental Windows security monitoring prototype. It analyses Windows process creation events (Event ID 4688) and identifies selected suspicious PowerShell command-line indicators.



It is a learning and research project, not a replacement for Microsoft Defender or commercial antivirus software.



\### 2. Problem Statement

Windows records information about programs that start on a computer. However, raw event logs do not automatically explain which activities may deserve investigation.



ThreatLens demonstrates how Python can analyse process events and provide understandable detection results.



\### 3. Project Architecture

Windows Security Event Log (4688)

→ Python Event Collector

→ JSON Process Events

→ ThreatLens Detection Engine

→ NORMAL or FLAGGED result with explanation.



\### 4. Detection Rule

\*\*Rule ID: TL001\*\*



Detects PowerShell or PowerShell 7 command lines containing:

\- `-EncodedCommand`

\- `-enc`



A match is a suspicious indicator, not proof of malware.



\### 5. Technologies Used

\- Windows 11

\- Python

\- Windows Security Event Log

\- Event ID 4688

\- JSON

\- Python unittest



\### 6. Testing Results

Five automated tests passed:



1\. Encoded PowerShell command — FLAGGED.

2\. Short encoded command switch — FLAGGED.

3\. Normal Notepad — NORMAL.

4\. Normal PowerShell command — NORMAL.

5\. PowerShell 7 encoded command — FLAGGED.



Additional validation:

\- One saved Notepad event was analysed and classified as NORMAL.

\- Two synthetic events were analysed: one FLAGGED and one NORMAL.



\### 7. Limitations

\- Only one detection rule is implemented.

\- Encoded PowerShell can also be used legitimately.

\- No automatic process blocking is implemented.

\- No continuous monitoring is implemented.

\- This prototype is not production-ready.



\### 8. Future Improvements

\- Add more explainable detection rules.

\- Improve Windows event collection.

\- Add a user interface.

\- Evaluate false positives and false negatives.

\- Add more authorised test datasets.



\### 9. Safe Use

ThreatLens is intended for learning and authorised defensive testing. It does not execute commands found in event records.



\### 10. AI Assistance Disclosure

ChatGPT assisted with development guidance, code drafting, testing suggestions, and documentation. The project author is responsible for understanding and validating the implementation.
