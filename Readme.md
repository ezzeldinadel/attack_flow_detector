# 🛡️ Attack Flow Detector

**Find the MITRE ATT&CK flows sneakily hiding in your alerts, by making contextual groupings, then finding causal sequences.**

## 🔍 Overview

Attack Flow Detector is a Python-based tool designed to analyze security alerts and identify potential attack patterns based on the MITRE ATT&CK framework. By correlating events, it aims to uncover stealthy attack flows that might otherwise go unnoticed.

## 🚀 Features

- **Correlation Analysis**: Detects relationships between seemingly unrelated alerts.
- **MITRE ATT&CK Mapping**: Aligns detected patterns with known ATT&CK techniques.
- **Modular Design**: Easily extendable to incorporate additional data sources or detection logic.

## 📁 Project Structure

attack_flow_detector/ ├── correlation_test_py.py # Core script for correlation analysis ├── README.md # Project documentation

bash
Copy code

## ⚙️ Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/ezzeldinadel/attack_flow_detector.git
   cd attack_flow_detector
   ```
2. **Set up a virtual environment (optional but recommended):**

```bash
Copy code
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```
3. **Install dependencies:**


```bash
Copy code
pip install -r requirements.txt
```

## 🛠️ Contributing
Contributions are welcome! Please fork the repository and submit a pull request.

## 📄 License
This project is licensed under the MIT License. See the LICENSE file for details.

## 📬 Contact
For questions or suggestions, please open an issue on the GitHub repository.

Relevant tools:- 
https://github.com/cypienta/data_mapper_model
https://github.com/ezzeldinadel/attack_technique_detector
