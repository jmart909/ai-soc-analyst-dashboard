AI-Powered SOC Analyst Dashboard

An interactive cybersecurity dashboard that simulates real-world security operations center (SOC) workflows. This tool generates security logs, detects threats, and uses AI to analyze incidents.

🚀 Features
Simulated attack scenarios:
Brute Force
Credential Stuffing
Benign Activity
Threat detection engine:
Brute Force detection (MITRE T1110)
Credential Stuffing detection
AI-powered alert analysis:
Explains what happened
Identifies why it's suspicious
Assigns risk level
Recommends actions
Interactive dashboard:
Metrics (logs, alerts, failures)
Attack visualization charts
Timeline of events
Real log ingestion:
Upload CSV or JSON logs
Response simulation:
"Block IP" functionality

🛠️ Tech Stack
Python
Streamlit
Pandas
OpenAI

▶️ How to Run
pip install -r requirements.txt
streamlit run app.py

🔐 Environment Setup
Create a .env file:
OPENAI_API_KEY=your_api_key_here

📊 Example Use Cases
SOC analyst training
Threat detection simulation
AI-assisted incident response demos
Cybersecurity portfolio project

🧠 Future Improvements
Real SIEM integration
GeoIP visualization
Automated response actions
Advanced anomaly detection