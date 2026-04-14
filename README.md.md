Sentinel-Core is a modular, high-performance security auditing and threat-hunting tool developed for Linux environments. Built with an SRE mindset, it bridges the gap between manual system hardening and automated security monitoring.

Unlike monolithic scripts, Sentinel-Core uses a decoupled architecture to provide real-time insights into system integrity, suspicious log patterns, and advanced process anomalies (including fileless malware detection).
🚀 Key Features

    Modular Architecture: Decoupled logic (Logger, Scanner, Monitor) for high maintainability and scalability.

    Threat Hunting (Live): Real-time process monitoring with a focus on Fileless Malware detection (via /proc/$PID/exe verification) and suspicious path execution (/tmp, /dev/shm).

    SRE & Big Data Ready: Native JSON export support for seamless integration with ELK Stack, Splunk, or custom Grafana dashboards.

    Intelligent Log Auditing: High-speed RegEx engine to detect brute-force attacks, SSH anomalies, and terminal injection attempts.

    Zero-Trust Permission Audit: Deep-scan of SUID/SGID binaries and world-writable configuration files to prevent privilege escalation.

    Fingerprinting: Unique system ID generation for asset tracking in distributed environments.

🛠️ Architecture & Tech Stack

    Language: Bash (Gnu Coreutils)

    Logic: Modular shell scripting with external configuration management.

    Data Handling: jq for structured JSON output.

    Security Focus: FHS compliance, Unix permissions integrity, and process signal management (SIGSTOP/SIGKILL).

sentinel/
├── main.sh                # Main Orchestrator & CLI Entry point
├── sentinel.conf          # External Configuration (No Hardcoding)
├── lib/
│   └── globals.sh         # Environment variables & Global UI
├── modules/
│   ├── logger.sh          # Log Analysis & RegEx Engine
│   ├── scanner.sh         # File System & Permission Integrity
│   ├── monitor.sh         # Process Tracking & Signal Management
│   └── utils.sh           # Helper functions & JSON Logger
└── reports/               # Automated audit logging

💻 Installation & Usage
Prerequisites

    A Linux distribution (Tested on Arch Linux and AlmaLinux 9).

    Root privileges (sudo).

    jq (Required for JSON mode).

Quick Start
Bash

# Clone the repository
git clone https://github.com/gleiva/sentinel-core.git
cd sentinel-core

# Grant execution permissions
chmod +x main.sh

# Run the interactive dashboard
sudo ./main.sh

# Run in JSON mode for data pipelines
sudo ./main.sh --json

🛡️ Why Sentinel-Core?

This tool was developed to address the need for a lightweight, dependency-minimal security auditor that follows professional DevOps/SRE standards:

    Portability: Uses an external .conf file to avoid hardcoded paths.

    Observability: Transforms raw system noise into structured data.

    Response: Not just a scanner—Sentinel-Core allows for immediate incident response by managing process signals directly from the monitor.


👤 Author

Gonzalo Leiva

    Engineering Student @ Universidad de Montevideo (UM).

    Specialization: Cybersecurity (Blue Team), SRE, and Infrastructure as Code.

    Current Focus: Building high-performance concurrent tools in Go and advanced Linux hardening.

📄 License

This project is licensed under the MIT License - see the LICENSE file for details.