&#x20;Problem Statement — ThreatLens



1\. Problem



Windows records process creation events, including executable names, process IDs, command lines, and parent processes.



However, raw event logs do not automatically explain which activities may require security investigation.



2\. Proposed Solution



ThreatLens is a Python-based experimental tool that analyses Windows process creation events (Event ID 4688).



It:

1\. Reads process-event information from JSON files.

2\. Checks events against detection rules.

3\. Identifies selected suspicious indicators.

4\. Produces an explanation for every flagged event.

5\. Saves the analysis results in JSON format.



&#x20;3. Detection Rule



Rule TL001 identifies PowerShell or PowerShell 7 command lines containing `-EncodedCommand` or `-enc`.



This is a suspicious indicator, not confirmation of malicious activity.



&#x20;4. Intended Users



\- Cybersecurity students.

\- Beginners learning Windows security monitoring.

\- Security analysts experimenting with rule-based detection.

&#x20;5. Project Scope



Included:

\- Windows Event ID 4688 collection.

\- Python-based analysis.

\- Explainable detection results.

\- Automated tests.

\- Synthetic test data.



Not included:

\- Antivirus protection.

\- Automatic process blocking.

\- Production endpoint monitoring.

\- Machine-learning detection.

6\. Testing



Five automated tests passed.



The saved Notepad event was classified as NORMAL.



In the synthetic dataset, the encoded PowerShell event was FLAGGED and the Notepad event was NORMAL.

&#x20;7. Limitations



The current prototype contains only one detection rule. Encoded PowerShell commands can have legitimate uses. More testing and additional rules are needed before any operational deployment.
