
# Netstat Security Analyzer [![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](link) ![Static Badge](https://img.shields.io/badge/Validation-InProgress-purple) [![License](https://img.shields.io/badge/license-Pending-blue)](LICENSE)

A browser-based, client-side tool to analyze `netstat` output for security insights, powered by React, TypeScript, and the Google Gemini API. Upload your log file to get a comprehensive report on connections, listening ports, local services, and potential risks without your data ever leaving your browser.


---

## ✨ Features

- **💻 Multi-Platform Support**: Parses standard `netstat` output from **Windows, Linux, and macOS**.
- **🛡️ Overall Risk Assessment**: Get an immediate, high-level overview of your system's security posture, categorized from Minimal to Critical.
- **📊 Comprehensive Dashboards**:
    - **Overall Risk**: A top-level summary of your security posture.
    - **Overview**: Key findings, AI security briefing, and top risky port activity.
    - **Local Services**: Deep-dive into services running on the loopback interface (`127.0.0.1`).
    - **Risky Connections**: Filter and search through all connections flagged for attention.
    - **Risk Matrix**: A granular, cell-by-cell matrix of all unique network interactions (Local &harr; Foreign).
    - **Port Usage**: Aggregated statistics for all local and foreign ports.
    - **IP Analysis**: Review all external IPs involved in connections.
- **🤖 AI-Powered Insights (with Google Gemini)**:
    - **AI Security Briefing**: Get a concise, AI-generated summary of the analysis.
    - **IP Reputation Analysis**: Use Google Search-grounded AI to check the reputation of any external IP.
    - **Local Service Identification**: Understand the purpose of services running on your local machine.
    - **Contextual Port Analysis**: Receive AI-driven explanations and recommendations for specific exposed ports.
- **🕰️ Historical Analysis & IP Timeline**:
    - Upload multiple analysis files to create a history of snapshots.
    - Track a specific IP address's activity across all your historical snapshots.
- **📄 Reporting**:
    - **HTML Report**: Generate a standalone, user-friendly HTML report for sharing or archiving.
    - **JSON Export**: Download the complete, raw analysis data in JSON format for use in other tools.
- **🔒 Client-Side Privacy**: All file parsing and analysis (excluding optional AI features) happen entirely in your browser. Your `netstat` log is never uploaded to a server.
- **🆘 In-App Help**: A comprehensive Help & FAQ section to guide you through generating `netstat` files and interpreting the results.

## 🚀 How to Use

1.  **Generate `netstat` Output**: Run a command on your system to generate a `netstat` log file. See the section below for commands.
2.  **Open the Application**: Launch the web app in your browser.
3.  **Upload File**: Click "Click to select netstat output file" and choose the `.txt` or `.log` file you just created.
4.  **Analyze**: Click the "Analyze & Add to History" button.
5.  **Explore**: Navigate through the various tabs (Overall Risk, Overview, Risky Conns, etc.) to explore the analysis.
6.  **Use AI (Optional)**: If you have a Gemini API key configured, use the "Get AI Insights" buttons for deeper analysis.
7.  **Export Report**: Click "Generate HTML Report" or "Export JSON" to save your analysis.

## 📋 Generating `netstat` Output

To get the best results, use the following commands to generate your input file.

### Windows

Open **Command Prompt** (run as **Administrator** for best results, as it provides Process IDs).

```sh
# Recommended: All connections, numeric format, owning process ID
netstat -ano > netstat_output.txt

# More detailed (includes executable names, larger file)
netstat -anob > netstat_output.txt
```

### Linux

Open your **Terminal**. Using `sudo` provides more complete process information.

```sh
# Recommended (modern systems): Shows TCP, UDP, Listening, Processes, Numeric
sudo ss -tulpn > netstat_output.txt

# Alternative (legacy systems)
sudo netstat -tulnp > netstat_output.txt
```

### macOS

Open **Terminal**.

```sh
# Standard command
netstat -an > netstat_output.txt
```

## 🤖 AI Integration (Google Gemini)

The AI-powered features rely on the Google Gemini API.

-   **API Key**: To enable these features, the application must be run in an environment where a Google GenAI API Key is available as an environment variable named `API_KEY`.
-   **No Key Input**: The application **does not** provide a UI to enter or manage your API key. It must be pre-configured in the deployment environment (e.g., via `process.env.API_KEY`).
-   **Privacy**: When you use an AI feature, a carefully crafted prompt containing **only the relevant, anonymized data** from the analysis (e.g., IP addresses, port numbers, connection counts) is sent to the Gemini API. The full content of your `netstat` file is **not** sent.

## 🛠️ Technology Stack

-   **Frontend**: [React](https://react.dev/), [TypeScript](https://www.typescriptlang.org/)
-   **Styling**: [Tailwind CSS](https://tailwindcss.com/)
-   **AI**: [Google Gemini API (`@google/genai`)](https://github.com/google/generative-ai-js)
-   **Icons**: [Lucide React](https://lucide.dev/)

## ⚠️ Disclaimer

This Netstat Security Analyzer is provided for **informational and educational purposes only**.

-   It is **not** a substitute for professional security audits, dedicated security software (like firewalls or antivirus), or expert consultation.
-   The accuracy of the analysis depends on the quality of the `netstat` data provided.
-   AI-generated insights are suggestions and should be critically reviewed and verified. The AI can make mistakes.
-   The creators of this tool are not responsible for any actions taken based on the information provided. Use at your own risk.

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.
