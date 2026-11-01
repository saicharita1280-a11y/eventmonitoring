
# 🛡️ SecureWatch
## Windows Event Log Monitoring and Security Analysis System

### Project Description

SecureWatch is a Python-based Windows Event Log Monitoring
and Security Analysis Dashboard developed using Streamlit.

The system helps users analyze Windows event logs, identify
errors and warnings, monitor security-related activities,
and detect selected suspicious events.

### Features

- Windows EVTX and CSV file upload
- Interactive event monitoring dashboard
- Critical, error, warning and information classification
- Failed login event analysis
- Security alert center
- Event ID and message filtering
- Interactive charts and event timeline
- Individual event details
- CSV report download
- Demonstration data

### Technologies Used

- Python
- Streamlit
- Pandas
- Plotly
- Python-Evtx

### How to Run

Install the required libraries:

pip install -r requirements.txt

Run the application:

streamlit run app.py

### Data Source

Windows Event Viewer exported EVTX or CSV files.

Demonstration data is also provided for testing.

### Project Purpose

To provide a simple and interactive platform for
Windows event monitoring and basic security analysis.
