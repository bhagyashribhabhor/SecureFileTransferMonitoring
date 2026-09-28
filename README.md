# Secure File Transfer Monitoring System

A Python-based cybersecurity project that monitors file activity, detects potentially sensitive file transfers, checks file integrity using SHA-256 hashing, calculates risk scores, and maintains security audit logs.

## 📌 Project Overview

The **Secure File Transfer Monitoring System** is designed to monitor file activities within a selected directory and identify potentially risky file operations.

The system detects events such as:

* File creation
* File modification
* File deletion
* File movement
* File transfer/copy activity
* Sensitive file activity
* Suspicious destination activity
* File integrity failures

The system assigns a risk score to detected activities and classifies them as **LOW, MEDIUM, or HIGH** risk.

## 🎯 Objectives

The main objectives of this project are:

* Monitor file activities in real time.
* Detect files containing sensitive information.
* Identify suspicious file destinations.
* Verify file integrity using SHA-256 hashing.
* Calculate risk scores for file activities.
* Generate security alerts for risky activities.
* Maintain audit logs for security analysis.
* Generate a security report from monitored activities.

## ✨ Features

### 1. File Activity Monitoring

The system monitors file operations such as:

* CREATE
* MODIFY
* DELETE
* MOVE
* TRANSFER/COPY

### 2. Sensitive File Detection

Files containing sensitive keywords are identified.

Sensitive keywords include:

```text
confidential
password
secret
credentials
private
```

### 3. Suspicious Destination Detection

The system checks for suspicious destination names such as:

```text
usb
external
cloud
network
shared
downloads
transfer
```

### 4. File Integrity Verification

The system calculates a **SHA-256 hash** for monitored files.

The hash can be compared with the previously recorded value to detect unexpected file changes.

### 5. Risk Scoring

The system calculates a risk score based on detected conditions.

| Condition              | Score |
| ---------------------- | ----: |
| Sensitive file         |   +40 |
| Suspicious destination |   +40 |
| Integrity failure      |   +30 |
| File deleted           |   +10 |
| File moved             |   +10 |

The maximum risk score is limited to **100**.

### 6. Risk Classification

| Risk Score | Severity |
| ---------: | -------- |
|       0–39 | LOW      |
|      40–69 | MEDIUM   |
|     70–100 | HIGH     |

### 7. Audit Logging

File activities are recorded for security analysis.

The audit information can contain:

* Timestamp
* User
* Event
* Source
* Destination
* Sensitive status
* SHA-256 hash
* Risk score
* Severity

### 8. Security Report Generation

The project includes a report generator that summarizes monitored activity and security events.

The report can provide:

* Total events
* Created files
* Modified files
* Deleted files
* Moved files
* Sensitive file events
* High-risk events
* Medium-risk events
* Low-risk events
* Unauthorized transfer events
* Integrity alerts

## 🛠️ Technologies Used

* **Python**
* **Watchdog**
* **SHA-256**
* **CSV**
* **File System Monitoring**
* **Windows PowerShell**
* **Git & GitHub**

## 🏗️ Project Structure

```text
SecureFileTransferMonitoring/
│
├── file_monitor.py
├── report_generator.py
├── README.md
└── .gitignore
```

Generated files such as audit logs, security reports, and test folders are intentionally excluded from the GitHub repository.

## ⚙️ How to Run

### Step 1: Clone the repository

```bash
git clone https://github.com/bhagyashribhabhor/SecureFileTransferMonitoring.git
```

### Step 2: Open the project directory

```bash
cd SecureFileTransferMonitoring
```

### Step 3: Install the required library

```bash
pip install watchdog
```

### Step 4: Start the file monitor

```bash
python file_monitor.py
```

The monitoring system will start observing file activity in the configured directory.

### Step 5: Generate the security report

```bash
python report_generator.py
```

## 🔄 System Workflow

```text
File Activity
      ↓
File Monitor
      ↓
Event Detection
      ↓
Sensitive File Detection
      ↓
Destination Check
      ↓
SHA-256 Integrity Check
      ↓
Risk Score Calculation
      ↓
Severity Classification
      ↓
Audit Logging
      ↓
Security Report
```

## 🔐 Example Risk Analysis

For example, if a sensitive file is transferred to a suspicious destination:

```text
Sensitive File       +40
Suspicious Destination +40
--------------------------------
Risk Score             80/100
Severity               HIGH
```

If an integrity failure is also detected:

```text
Sensitive File       +40
Suspicious Destination +40
Integrity Failure    +30
--------------------------------
Risk Score            110
Final Score           100/100
Severity              HIGH
```

## 🧪 Testing

The project was tested using different file activities, including:

* Creating normal files
* Creating sensitive files
* Modifying files
* Moving files
* Simulating file transfers
* Testing suspicious destinations
* Testing SHA-256 integrity changes
* Generating security reports

The generated monitoring output was used to verify event detection, risk scoring, and security classification.

## 📊 Project Output

The system provides monitoring information such as:

```text
SECURE FILE TRANSFER MONITOR

Event: FILE CREATED
Source: .\example.txt
User: bhagy
Sensitive: NO
Suspicious Destination: NO
SHA-256: <hash>
Risk Score: 0/100
Severity: LOW

✔ Normal activity.
```

For a sensitive or suspicious activity, the system can generate a higher risk score and corresponding severity level.

## ⚠️ Limitations

* The current project is intended as a practical file-monitoring prototype.
* Monitoring is performed within the configured directory.
* It does not guarantee complete operating-system-wide detection of every USB, network, or cloud transfer.
* Advanced enterprise-level endpoint monitoring is outside the current project scope.
* Authentication and centralized security management are not included in the current version.

## 🔮 Future Scope

Future versions can include:

* Real-time email alerts
* SMS or mobile notifications
* Database-based audit storage
* Web-based security dashboard
* Advanced USB monitoring
* Network transfer monitoring
* Cloud storage monitoring
* User authentication
* Role-based access control
* Machine-learning-based anomaly detection
* Centralized security monitoring
* Improved forensic analysis

## 🎓 Project Purpose

This project was developed as part of a **Cybersecurity Internship** to demonstrate practical knowledge of:

* File system monitoring
* Cybersecurity event detection
* File integrity verification
* SHA-256 hashing
* Risk assessment
* Security logging
* Python programming
* Security report generation

## 👩‍💻 Developer

**Bhagyashri Bhabhor**

## 🔗 GitHub Repository

https://github.com/bhagyashribhabhor/SecureFileTransferMonitoring
