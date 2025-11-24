# ryk_analysis_response
To Provide Solution for ryk

## Repository Contents

### Analysis Tools
- `decrypt.py` - Decrypts RYK ransomware encrypted files (requires valid decryption key)
- `ryuk.yara` - YARA rules for RYK ransomware detection using IOCs
- `check_digitalsig.ps1` - PowerShell script to verify digital signatures of binary files

### SIEM Integration
- `SecuritySolution_Rules/for_client/ossec.conf` - Wazuh agent configuration for log collection and FIM
- `SecuritySolution_Rules/for_client/sysmon_ryk_client.xml` - Sysmon configuration for RYK-specific event logging  
- `SecuritySolution_Rules/for_server/local_rules.xml` - Wazuh server rules to process Sysmon events
- `SecuritySolution_Rules/Rule_backup.zip` - Contains verified rule files (ossec.conf, sysmon_ryk_client.xml, local_rules.xml) that have been thoroughly tested. If you encounter issues with the individual files above, extract and use these backup configurations instead.

## Reconstructing RYK C2 Communication Despite Server Shutdown

Since the original C2 server (drmon.chickenkiller.com) was already down, I reconstructed the communication infrastructure using REMNUX to create comprehensive security detection rules.

## Lab Setup

### Lab Overview
```
┌─────────────────────────┐    ┌─────────────────────────┐    ┌─────────────────────────┐
│    Wazuh Server +       │    │     Malware Client      │    │    FakeDNS + WebSrv     │
│    Elastic ELK          │    │     (FLARE-VM)          │    │       (REMNUX)          │
│                         │    │                         │    │                         │
│  OS: Ubuntu             │    │  OS: Windows 10         │    │  OS: Ubuntu             │
│  IP: 10.10.10.132       │    │  IP: 10.10.10.128       │    │  IP: 10.10.10.134       │
│  Role: SIEM + Analytics │    │  DNS: 10.10.10.134 ──────────│  Role: C2 Simulation    │
│                         │    │  Role: Malware Target   │    │                         │
│  Services:              │    │                         │    │  Services:              │
│  - Wazuh Manager        │    │  Services:              │    │  - FakeDNS              │
│  - Elasticsearch        │    │  - Wazuh Agent          │    │  - Python HTTP Server   │
│  - Kibana               │    │  - Sysmon               │    │  - Malware Hosting      │
│                         │    │                         │    │                         │
└─────────────────────────┘    └─────────────────────────┘    └─────────────────────────┘
            │                              │                              │
            └──────────────────────────────┼──────────────────────────────┘
                                          │
                                   Lab Network
                                  10.10.10.0/24

Data Flow:
1. FLARE-VM executes malware
2. DNS queries → REMNUX (FakeDNS)
3. HTTP requests → REMNUX (Python server)
4. Security events → Wazuh Server
5. Analysis & Alerts → ELK Dashboard
```

### 1. REMNUX Configuration
**DNS Resolution Setup:**
Configure FakeDNS to resolve drmon.chickenkiller.com to the REMNUX IP address:
```bash
root@remnux:/home/remnux# fakedns --resolve drmon.chickenkiller.com 10.10.10.134
```
![ReMNUX - fakedns](https://github.com/user-attachments/assets/a97bfc07-0145-4ee3-8faf-1b1546393558)  
(ReMNUX - fakedns)

*Note: Since the original C2 server (182.228.44.206) is no longer active, we redirect DNS queries to our REMNUX host (10.10.10.134) to simulate the C2 infrastructure. This allows us to recreate the complete attack chain for security rule development and testing purposes.*
```
This placement makes sense because:
1. It immediately explains why you're using a different IP address
2. It provides context right where the DNS configuration happens
3. It helps readers understand the lab setup methodology
4. It's positioned early enough to set proper expectations for the entire lab setup
```

**Web Service Setup:**
Host the svchost binary using Python's built-in web server:

```bash
root@remnux:/home/remnux/malware# python3 -m http.server 80
```
*Note: Place the svchost file in the malware directory before starting the web server*

![ReMNUX - Start Web Service to Response GET Method](https://github.com/user-attachments/assets/425ec6c3-c833-4cc8-933e-05245ba4b8e8)  
(ReMNUX - Start Web Service to Response GET Method)

*Note: The upper image shows the client successfully retrieving svchost via GET method. The subsequent POST request shows the client attempting to send AES key data in JSON format `{"enc_data":"AES_KEY_VALUE","id":"uuid"}`, but since the basic Python server only accepts GET requests, this results in an error.*

### 2. Windows Client Configuration
**Update Wazuh Agent Configuration:**
Replace the ossec.conf file with the provided configuration:
```
File: C:\Program Files (x86)\ossec-agent\ossec.conf
Source: ryk_analysis_response/SecuritySolution_Rules/for client/ossec.conf
```

**Restart Wazuh Agent:**
1. Launch `C:\Program Files (x86)\ossec-agent\win32ui.exe`
2. Navigate to "Manage" tab → "Restart"
3. Verify status: "Manage" tab → "Status"

![Client - Restart Wazuh Agent](https://github.com/user-attachments/assets/e6269ed7-463e-4add-a06c-c3281d85bedb)  
(Client - Restart Wazuh Agent)

**Configure Sysmon:**
Replace the existing Sysmon configuration:
```cmd
.\Sysmon64.exe -c .\sysmon_ryk_client.xml
```
*Source: ryk_analysis_response/SecuritySolution_Rules/for client/sysmon_ryk_client.xml*

Install Sysmon Service:
```cmd
.\Sysmon64.exe -i .\sysmon_ryk_client.xml
```

### 3. Wazuh Server Configuration
**Update Detection Rules:**
Replace the local rules file:
```bash
File: /var/ossec/etc/rules/local_rules.xml
Source: ryk_analysis_response/SecuritySolution_Rules/for server/local_rules.xml
```

![Wazuh Server - local_rules.xml location](https://github.com/user-attachments/assets/a0f9d810-d326-4ae5-9184-5951b21f21b8)  
(Wazuh Server - local_rules.xml location)

**Restart Wazuh Manager:**
```bash
systemctl restart wazuh-manager
```

![Wazuh Server - Checking wazuh-manager status](https://github.com/user-attachments/assets/58dc5202-dda1-4737-b064-623349bfbb13)  
(Wazuh Server - Checking wazuh-manager status)

### 4. Execution
1. Clear Sysmon event logs for clean testing
2. Execute the malicious document to trigger the macro
3. Monitor detection alerts in Wazuh dashboard

This setup successfully simulates the complete RYK ransomware attack chain while providing comprehensive detection coverage through coordinated Sysmon and Wazuh rules.

### Proof of Detection Results

![Client - Sysmon Detected fodhelper process](https://github.com/user-attachments/assets/a16c0aa5-38fd-487e-a1ac-c0cb0312da0d)  
(Client - Sysmon Detected fodhelper process)

![Client - Sysmon Detected C2 DNS Resolution](https://github.com/user-attachments/assets/18e31c41-cafe-4c45-bfa5-57c2a1bc085a)  
(Client - Sysmon Detected C2 DNS Resolution)

![Wazuh Server - Wazuh+Elastic ELK Dashboard](https://github.com/user-attachments/assets/ba11af4a-46a0-43e7-aba1-83773559f72a)
(Wazuh Server - Wazuh+Elastic ELK Dashboard)

![Wazuh Server - Detected Suspicious Activities from RYK ransomware](https://github.com/user-attachments/assets/2cd1ba15-c50c-455e-9c2a-b5dbb64d2d31)  
(Wazuh Server - Detected Suspicious Activities from RYK ransomware)

![Wazuh Server - Detailed Log](https://github.com/user-attachments/assets/f17fc2a5-ed1d-43e9-8dab-9e7a8850646c)  
(Wazuh Server - Detailed Log)

### Update Log

2025-08-28: Add yara rule, decrypt.py  
2025-09-02: Add Check_digitalsig.ps1  
2025-09-06: Add Wazuh+Sysmon Rules  
2025-09-13: Update Wazuh+Sysmon Rules (enhanced detection for malware artifacts with improved Wazuh+ELK logging)

### Known Issues

- **File Extension Detection**: Sysmon's FileCreate event cannot detect file modifications where the RYK ransomware appends the .ryk extension to existing files. Although the detection strategy was changed to use Syscheck in ossec.conf, file extension changes remain undetected.

- **Registry Modification Detection**: The RYK ransomware modifies registry keys to bypass UAC, but neither Sysmon events (12-14) nor ossec.conf's Syscheck can detect modifications to the specific registry path `ms-settings\Shell\Open\Command`. Other registry key modifications are detected normally(from sysmon).

- **Documentation**: Deployment procedures require further expansion and detailed troubleshooting guides.
