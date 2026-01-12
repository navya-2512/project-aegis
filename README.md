# Project Aegis 🛡️
LLM Firewall / AI WAF

Project Aegis is a lightweight security proxy to protect LLM applications against:
- **Prompt Injection**
- **Sensitive Information Disclosure (DLP / data leakage)**

It filters inbound prompts, forwards safe requests to the LLM, and redacts sensitive data in outbound responses.


##Features
- **FastAPI proxy/middleware pipeline**
- Inbound **prompt injection detection** (rule-based, optional ML path)
- Outbound **DLP redaction** using **spaCy NER + regex**
- Logging & monitoring support (hackathon MVP)
- OWASP-style security testing + load testing (Locust)

---

## Tech Stack
FastAPI, Python, Streamlit, SQLite, spaCy, Regex

---

##  Setup
```bash
git clone https://github.com/<your-username>/project-aegis.git
cd project-aegis
pip install -r requirements.txt
python app.py
