# 🛡️ Attack Flow Detector

**Find the MITRE ATT&CK flows sneakily hiding in your alerts, by making contextual groupings, then finding causal sequences.**

___
<p align="center">
<a> <img src="https://badges.frapsoft.com/os/v3/open-source.svg?v=103"></a>
<a> <img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
<a> <img src="https://img.shields.io/pypi/l/mia.svg"></a>
<a href="https://https://github.com/ezzeldinadel/attack_flow_detector/issues"><img alt="GitHub issues" src="https://img.shields.io/github/issues/ezzeldinadel/attack_flow_detector"></a>
<a href="https://github.com/ezzeldinadel/attack_flow_detector/graphs/contributors" alt="Contributors"> <img src="https://img.shields.io/github/contributors/ezzeldinadel/attack_flow_detector" /></a>
<a href="https://github.com/ezzeldinadel/attack_flow_detector/graphs/stars" alt="Stars"><img src="https://img.shields.io/github/stars/ezzeldinadel/attack_flow_detector" /></a>
<a href="https://github.com//ezzeldinadel/attack_flow_detector"><img alt="GitHub forks" src="https://img.shields.io/github/forks/ezzeldinadel/attack_flow_detector"></a>

<br>
 <p align="center">
   <a> <img src="https://img.shields.io/badge/langchain-1C3C3C?style=for-the-badge&logo=langchain&logoColor=white" /></a>
  <a>  <img src="https://img.shields.io/badge/ChatGPT-74aa9c?style=for-the-badge&logo=openai&logoColor=white" style="display: block; margin-left: auto; margin-right: auto;" /></a> 
   <a><img src="https://img.shields.io/badge/-HuggingFace-FDEE21?style=for-the-badge&logo=HuggingFace&logoColor=black" /></a>
   <a><img src="https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54" /></a>
</p>



## 🔍 Overview

Attack Flow Detector is a Python-based tool designed to analyze security alerts and identify potential attack patterns based on the MITRE ATT&CK framework. By correlating events, it aims to uncover stealthy attack flows that might otherwise go unnoticed.

## 🚀 Features

- **Correlation Analysis**: Detects relationships between seemingly unrelated alerts.
- **MITRE ATT&CK Mapping**: Aligns detected patterns with known ATT&CK techniques.
- **Modular Design**: Easily extendable to incorporate additional data sources or detection logic.

## ⚙️ Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/ezzeldinadel/attack_flow_detector.git
   cd attack_flow_detector
   ```
2. **Set up a virtual environment (optional but recommended):**

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```
3. **Install dependencies:**


```bash
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
