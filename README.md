# Phishing Email Analysis 3

### **Instructions:**

- You are a SOC Analyst at Global Logistics. The SOC received an alert about a quarantined email that was flagged by the company's email gateway solution. The email was sent to Emily Nguyen, a member of the marketing team, from her friend Alexia Barry. As the analyst assigned to this ticket, your task is to review the email to determine if the email is safe to release to Emily's inbox or if further action is needed.
- Using what you've learned within this domain, perform a detailed email analysis on the challenge3.eml file to answer the report questions below.

### **Challenge Questions:**

**Challenge File**

- `01_Phishing_Analysis/Challenges/challenge3.eml`

Q1 Based on the contents of the email header, what is the full date and time of the email delivery?

- `Tue, 14 May 2024 23:31:08 +0000`

Q2 What is the subject of the email?

- `You're Invited!`

Q3 Who was the email sent to?

- `emily.nguyen@glbllogistics.co`

Q4 Based on the sender's display name, who does the email claim to be from?

- `Adam Barry`

Q5 What is the sender's email address?

- `abarry@live.com`

Q6 What email infrastructure or provider was used to send the email?

- `Microsoft`

Q7 What is email's Message ID?

- `SA1PR14MB737384979FDD1178FD956584C1E32@SA1PR14MB7373.namprd14.prod.outlook.com`

Q8 Run [emldump.py](http://emldump.py/) against the email file. Which index number contains the file attachment?

- `5`

Q9 What is the filename of the attachment?

- `AR_Wedding_RSVP.docm`

Q10 What is the SHA-256 hash of the attachment?

- `41c3dd4e9f794d53c212398891931760de469321e4c5d04be719d5485ed8f53e`

Q11 Submit the hash value to VirusTotal. What is the Popular threat label returned for this sample?

- `downloader.autdwnlrner/w97m`

Q12 [Yes or No] - After your analysis, should the email be released to the user's inbox?

- `No`

[Bonus] Perform static analysis on the malicious document and its embedded VBA macro. What URL does the malware attempt to download an executable from? Provide the URL in defanged format.

- `hxxps[://]github[.]com/tcwus/pastebin-uploader[.]exe`

[Bonus] Perform static analysis on the malicious document and its embedded VBA macro. What is the filename used by the macro to save the executable?

- `shost.exe`

### Challenge URL

- [`https://challenges.malwarecube.com/#/c/763f7d78-84c4-465f-9c7d-085e33e21d64`](https://challenges.malwarecube.com/#/c/763f7d78-84c4-465f-9c7d-085e33e21d64)

---

## Challenge 3 Report

![Image 1](https://raw.githubusercontent.com/0xCR0NW0L7/Phishing-Email-Analysis-3/main/img/image.png)  

## Headers

|  **Header**  |  **Value**  |
| --- | --- |
| Date | `Tue, 14 May 2024 23:31:08 +0000` |
| Subject | `You're Invited!` |
|  From  | `abarry@live.com` |
|  To  | `emily.nguyen@glbllogistics.co` |
|  Reply-To  | NA |
|  Return-Path  | `abarry@live.com` |
|  Sender IP  | `2a01:111:f403:2c14::801` |
|  Resolved Host  | `SA1PR14MB7373.namprd14.prod.outlook.com` |
|  Message-ID  | `SA1PR14MB737384979FDD1178FD956584C1E32@SA1PR14MB7373.namprd14.prod.outlook.com` |

## URLs

- **No URLs in the email body** itself.
- The **malicious macro** inside the `AR_Wedding_RSVP.docm` attempts to download an executable from `hxxps[://]github[.]com/tcwus/pastebin-uploader[.]exe`

## Attachments

| **File Name** | `AR_Wedding_RSVP.docm` |
| --- | --- |
| **MD5** | `590d3c98cb5e61ea3e4226639d5623d7` |
| **SHA1** | `91091f8e95909e0bc83852eec7cac4c04e1a57c3` |
| **SHA256** | `41c3dd4e9f794d53c212398891931760de469321e4c5d04be719d5485ed8f53e` |

## Description

This email claims to be a wedding RSVP invitation from "Adam Barry" but contains a **malicious Word document attachment** (`.docm`) that executes a downloader macro. The email was quarantined by the SOC due to the suspicious attachment.

**The analysis includes:**

- Verification of **email authentication mechanisms** (SPF, DKIM, DMARC)
- Examination of **attachments** for malicious macros
- URL analysis from embedded macros (malware download links)

## Artifact Analysis

- Sender Analysis:
    - SPF = pass, DKIM = pass, DMARC = pass
    - Email originates from `live.com` via Microsoft Outlook infrastructure
    
    ```bash
    C:\Users>nslookup -TXT=record 2a01:111:f403:2c14::801
    *** Invalid option: TXT=record
    Server:  UnKnown
    Address:  fe80::866e:bcff:fef2:7101
    
    Name:    mail-bn8nam11olkn20801.outbound.protection.outlook.com
    Address:  2a01:111:f403:2c14::801
    
    ```
    
- URL Analysis:
    - No URLs directly in email body
    - VBA macro attempts to download executable from `hxxps[://]github[.]com/tcwus/pastebin-uploader[.]exe`
- Attachment Analysis:
    
    ```bash
    $ python ~/Desktop/tools_soc/emldump.py challenge3.eml 
    Warning: the first block contains lines that are not a field.
    1: M         multipart/mixed
    2: M         multipart/alternative
    3:       428 text/plain
    4:       833 text/html
    5:    143590 text/plain (AR_Wedding_RSVP.docm)
    
    ```
    
    ```bash
    $ sha256sum "$MALWARE_FILE" && sha1sum "$MALWARE_FILE" && md5sum "$MALWARE_FILE"
    6c3333fbe9d79c948897b42138c8243228875f0bc657cdbe2d9e5bd0c2d62198  AR_Wedding_RSVP.docm
    6b5eb07386ddba87a384208499f2c5d347a4d5f5  AR_Wedding_RSVP.docm
    238bc01287676144876cdc4bcbfeda2a  AR_Wedding_RSVP.docm
    
    ```
    

## Verdict

- Email consists of a **malicious document**
- Contains a **malicious macro downloader**
- Should **not** be released to the user's inbox

## Defense Actions

- Quarantine the email permanently
- Block sender and attachment hash in the security gateway
- Alert and educate the user about this phishing/malware attempt
- Submit IoCs (attachment hash, macro URL) to threat intelligence platform
- Perform an endpoint scan for any execution of `shost.exe`

## Screenshots

1. Reverse DNS Lookup

![Image 2](https://raw.githubusercontent.com/0xCR0NW0L7/Phishing-Email-Analysis-3/main/img/image%201.png)  

2. VirusTotal Attachmenet Scan

![Image 3](https://raw.githubusercontent.com/0xCR0NW0L7/Phishing-Email-Analysis-3/main/img/image%202.png)  

![Image 4](https://raw.githubusercontent.com/0xCR0NW0L7/Phishing-Email-Analysis-3/main/img/image%203.png)  

3. CISCO Talos Check

![Image 5](https://raw.githubusercontent.com/0xCR0NW0L7/Phishing-Email-Analysis-3/main/img/image%204.png)  

4. MalwareBazar Attahment Analysis

![Image 6](https://raw.githubusercontent.com/0xCR0NW0L7/Phishing-Email-Analysis-3/main/img/image%205.png)  

![Image 7](https://raw.githubusercontent.com/0xCR0NW0L7/Phishing-Email-Analysis-3/main/img/image%206.png)
