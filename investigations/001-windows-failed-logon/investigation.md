# Investigation 001: Windows Failed Logon Followed by Successful Logon

**Date:** 17 August 2026  
**Case Type:** Identity and Authentication  
**Environment:** Home SOC Lab — Windows 10 VM  
**Data Sources:** Windows Security Event Log and Microsoft Sentinel `SecurityEvent` table  
**Tools:** Windows Event Viewer, Microsoft Sentinel and KQL

## Scenario

As part of my SOC home lab, I generated two failed Windows logon attempts followed by a successful logon.

I investigated the Windows Security logs to determine what happened and whether the authentication activity should be classified as benign, suspicious or malicious.

The original investigation was performed in Windows Event Viewer. After connecting the lab endpoint to Microsoft Sentinel, I completed a follow-up review of the collected security telemetry using KQL.

## Investigation Question

Do the failed authentication events indicate normal user error or potentially suspicious authentication activity?

## Evidence

### Authentication Event Timeline

The Windows Security log was filtered for Event IDs `4624` and `4625` to correlate failed and successful authentication activity.

![Filtered Windows authentication events](screenshots/01-event-timeline.png)

### Event 1 — Failed Logon

- **Event ID:** `4625`
- **Time:** 03:25:05 AM
- **Account:** `khush`
- **Host:** `DESKTOP-58BSHCM`
- **Logon Type:** `2` — Interactive
- **Status:** `0xC000006D`
- **Substatus:** `0xC000006A`
- **Source Network Address:** `127.0.0.1`
- **Caller Process:** `svchost.exe`
- **Logon Process:** `User32`
- **Authentication Package:** `Negotiate`

#### Failed Logon Evidence

![Windows Event 4625 failed logon](screenshots/02-failed-logon-4625.png)

The event shows a failed authentication for account `khush` using Logon Type `2` — Interactive.

![Windows Event 4625 failure details](screenshots/03-failure-details-4625.png)

The failure details show Status `0xC000006D`, Substatus `0xC000006A` and Source Network Address `127.0.0.1`.

### Event 2 — Failed Logon

- **Event ID:** `4625`
- **Time:** 03:25:58 AM
- **Account:** `khush`
- **Host and Logon Type:** Same as the first event
- **Failure pattern:** Same as the first event

The second event records another failed interactive authentication attempt for the same account on the same endpoint.

![Additional Event 4625 evidence](screenshots/04-failure-event-logon.png)

### Event 3 — Successful Logon

- **Event ID:** `4624`
- **Time:** 03:26:10 AM
- **Account:** `khush`
- **Host:** `DESKTOP-58BSHCM`
- **Logon Type:** `2` — Interactive
- **Elevated Token:** No
- **Virtual Account:** No

#### Successful Logon Evidence

![Windows Event 4624 successful logon](screenshots/05-successful-logon-4624.png)

The subsequent Event ID `4624` records a successful Logon Type `2` authentication on the same Windows host.

## Timeline

| Time | Event ID | Result |
|---|---:|---|
| 03:25:05 AM | 4625 | Failed logon |
| 03:25:58 AM | 4625 | Failed logon |
| 03:26:10 AM | 4624 | Successful logon |

## Analysis

Windows Event ID `4625` records a failed logon attempt, while Event ID `4624` records a successful logon.

Both failed attempts involved the same account and host. Substatus `0xC000006A` indicates that an incorrect password was supplied for the account.

The events used Logon Type `2`, indicating interactive logon activity. The failed events also showed the loopback address `127.0.0.1`.

Together, these fields are consistent with local interactive authentication and provide no evidence in these events of a remote network-originated authentication attempt.

The two failures were followed 12 seconds later by a successful Logon Type `2` authentication using the same account.

## Classification

**Likely benign authentication activity**

## Reasoning

The observed pattern is consistent with a user entering an incorrect password twice and then successfully entering the correct password.

Factors supporting this assessment include:

- only two failed attempts;
- the same account and host across the events;
- Logon Type `2` interactive authentication;
- incorrect-password substatus;
- loopback source address on the failed events; and
- successful authentication shortly after the failures.

Based on the available telemetry, I found insufficient evidence to classify the activity as malicious or suspicious.

## MITRE ATT&CK Mapping

I would not map this activity to `T1110 — Brute Force` based only on these events.

Two failed local interactive logons followed by a successful logon do not provide sufficient evidence of systematic credential guessing.

## Recommended Action

Close as likely benign. No containment is required based on the available evidence.

If this occurred in a production environment, I would document the investigation and follow the organisation’s escalation procedures if additional suspicious indicators were identified.

## What Would Make This Suspicious?

I would investigate further or consider escalation if I observed:

- a large number of failed authentication attempts;
- failures involving multiple accounts;
- a remote or unexpected source;
- unusual logon types;
- authentication involving a privileged account;
- repeated failures over an extended period;
- the user reporting that they did not attempt the logon; or
- suspicious activity occurring after the successful authentication.

## Microsoft Sentinel Follow-Up

After completing the original investigation in Windows Event Viewer, I verified that Windows Security events from the lab endpoint were reaching the `SecurityEvent` table in Microsoft Sentinel.

This confirmed the following telemetry path:

`Windows Security Event Log`  
→ `Azure Monitor Agent`  
→ `Data Collection Rule`  
→ `Log Analytics workspace`  
→ `Microsoft Sentinel`  
→ `SecurityEvent table`

I used the following KQL query to review recent security events:

```kql
SecurityEvent
| project TimeGenerated, Computer, EventID, Activity, Account, IpAddress
| sort by TimeGenerated desc
| take 50
```

### KQL Explanation

- `SecurityEvent` selects the table containing the collected Windows Security events.
- `project` keeps the fields needed for the review.
- `sort by TimeGenerated desc` displays the newest records first.
- `take 50` limits the result to 50 records.

The results included Event IDs `4624`, `4625` and `4627`.

Event ID `4627` provides group-membership information for a new logon. It does not mean that special privileges were assigned.

Event ID `4672` records special privileges assigned to a new logon. A `4672` event may be expected for administrator, service or system accounts and does not prove privilege escalation by itself.

A `4624` event and a `4627` event appearing close together on the same computer may be related. However, matching timestamps alone do not prove that they belong to the same logon session.

Stronger correlation would compare the relevant Logon ID, account, computer and timestamp. That Logon ID correlation was not completed during this follow-up, so I did not classify the activity as privilege escalation.

This follow-up moved the investigation from local Event Viewer evidence into a SIEM-based workflow while preserving the distinction between evidence and assumptions.

## Limitations

Post-logon process activity was not investigated during the original Event Viewer analysis because Event Viewer became unresponsive.

The later Sentinel follow-up verified ingestion and authentication-event visibility, but it did not establish whether suspicious activity occurred after the successful logon.

The Logon ID from the successful `4624` event was not used to correlate it with the `4627` event or with later activity.

No Sentinel analytics rule, alert or incident was created during Case 001.

The activity was generated using the normal lab account rather than a dedicated synthetic test account.

## Lessons Learned

This investigation helped me understand:

- the difference between Windows Event IDs `4625` and `4624`;
- why Logon Type matters during authentication triage;
- how Status and Substatus provide more detail than the event description alone;
- why authentication events should be correlated rather than investigated individually;
- the importance of distinguishing evidence from assumptions;
- why benign activity should not be unnecessarily mapped to MITRE ATT&CK techniques;
- how Windows Security events appear in Microsoft Sentinel;
- how KQL can reduce telemetry to investigation-relevant fields;
- the difference between Event IDs `4627` and `4672`;
- why Event ID `4672` is not proof of privilege escalation by itself; and
- why accurate correlation requires stronger fields than timestamp proximity.

For future lab testing, I will use a dedicated synthetic test account rather than my normal lab account.
