# 🛡️ Sentinel-Core: Advanced Linux Security Orchestrator

<p align="center">
  <img src="https://img.shields.io/badge/Bash-4E9A06?style=for-the-badge&logo=gnu-bash&logoColor=white" alt="Bash">
  <img src="https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black" alt="Linux">
  <img src="https://img.shields.io/badge/Security-Blue_Team-0055ff?style=for-the-badge" alt="Security">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT">
</p>

**Sentinel-Core** is a modular, high-performance security auditing and threat-hunting tool developed for Linux environments. Built with an **SRE mindset**, it bridges the gap between manual system hardening and automated security monitoring.

---

## 🚀 Key Features

* **🧱 Modular Architecture:** Fully decoupled modules for high maintainability.
* **🎯 Threat Hunting:** Focus on **Fileless Malware detection** via `/proc/$PID/exe`.
* **📊 SRE Ready:** Native **JSON export** for ELK Stack or Splunk integration.
* **🔍 Intelligent Logging:** RegEx-powered engine to detect brute-force and injections.
* **🛡️ Zero-Trust Audit:** Deep-scan of SUID/SGID and critical FHS permissions.

---

## ⚙️ Component Architecture

Este diagrama representa la orquestación de datos y la comunicación entre módulos.

```mermaid
graph TD
    %% Estilos
    classDef main fill:#1e1e2e,stroke:#89b4fa,stroke-width:2px,color:#cdd6f4;
    classDef module fill:#313244,stroke:#94e2d5,stroke-width:2px,color:#cdd6f4;
    classDef input fill:#1e1e2e,stroke:#f38ba8,stroke-width:1px,color:#cdd6f4,stroke-dasharray: 5 5;
    classDef output fill:#1e1e2e,stroke:#a6e3a1,stroke-width:2px,color:#cdd6f4;

    subgraph SentinelCore ["Orchestrator"]
        Main("main.sh - Entrypoint")
        Config("sentinel.conf - Config")
        Utils("utils.sh - Lib")
    end
    
    subgraph Modules ["Specialized Modules"]
        Logger("logger.sh - Logs")
        Monitor("monitor.sh - Process")
        Scanner("scanner.sh - Audit")
    end
    
    subgraph SystemInputs ["System Input"]
        Logs[/"auth.log" /]
        Procs[/"Process Table" /]
        FS[/"Filesystem" /]
    end

    Main --> Config
    Main --> Utils
    Main ==> Logger
    Main ==> Monitor
    Main ==> Scanner
    
    Logs -.-> Logger
    Procs -.-> Monitor
    FS -.-> Scanner

    Logger --> Reports("📁 reports/ Audit Logs")
    Scanner --> Reports
    Monitor --> LiveUI["🖥️ Live Dashboard"]

    class Main,Config,Utils main;
    class Logger,Monitor,Scanner module;
    class Logs,Procs,FS input;
    class Reports,LiveUI output;
```

💻 Installation & Usage
⚙️ Prerequisites

    OS: Arch Linux / AlmaLinux 9 / Debian 12.

    Privileges: Root access (sudo) is required.

    Dependencies: jq (for JSON output).

🚀 Quick Start

    Clone & Access:
    Bash

    git clone (https://github.com/gleiva-it/Sentinel-Core-Linux-Security-Orchestrator.git)
    cd Sentinel-Core-Linux-Security-Orchestrator

    Permissions:
    Bash

    chmod +x main.sh lib/globals.sh modules/*.sh

    Execution:
    Bash

    # Standard Mode
    sudo ./main.sh

    # Pipeline Mode (JSON)
    sudo ./main.sh --json

🛡️ Why Sentinel-Core?

    Portability: Zero hardcoded paths; everything is in sentinel.conf.

    Observability: Converts system noise into structured, actionable data.

    Active Response: Includes surgical tools to manage process signals (SIGSTOP, SIGKILL) during live monitoring.

👤 Author

Gonzalo Leiva

    🎓 Computer Science Student @ Universidad de Montevideo (UM).

    🛡️ Focus: Cybersecurity (Blue Team) & SRE.

    🛠️ Tech: Bash, Go, Python, Linux Hardening.

📄 License

Licensed under the MIT License.
