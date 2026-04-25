# AI-Powered SOC Threat Detection Dashboard

This project is something I built while exploring how real Security Operations Centers (SOC) work. The idea was simple — take system logs, analyze them, and try to spot anything suspicious in a clean and understandable way.

Instead of just reading logs manually, this dashboard helps in identifying potential threats automatically and gives a clearer picture of what’s happening inside a system.

---

## 🔍 What this project does

* Analyzes system log files to detect unusual or suspicious activity
* Checks IP addresses using threat intelligence APIs to see if they are malicious
* Detects phishing URLs to help identify unsafe links
* Displays everything in a simple dashboard so it’s easy to understand

---

## ⚙️ Built with

* Python
* Pandas (for handling log data)
* Streamlit (for the dashboard UI)
* Requests (for API calls)

---

## 🚀 How to run this project

1. Download or clone this repository
2. Install the required libraries:

   ```
   pip install -r requirements.txt
   ```
3. Run the application:

   ```
   streamlit run app.py
   ```

---

## 🔐 API setup

This project uses external APIs for IP reputation and phishing detection.

Create a `.env` file in your project folder and add your API keys like this:

```
ABUSEIPDB_API_KEY=your_api_key_here
PHISHING_API_KEY=your_api_key_here
```

---
## ⚙️ Setup Instructions

1. Clone the repository  
2. Install dependencies:
   pip install -r requirements.txt  
3. Create a `.env` file and add your API keys  
4. Run the app:
   streamlit run app.py  

## 💡 Why I built this

I wanted to understand how SOC tools actually work in real environments. This project is a small step towards that — combining log analysis, threat intelligence, and basic detection into one place.

---

## 🔮 What I plan to improve

* Real-time log monitoring instead of static files
* Sending alerts through email or messages
* Better UI and visualization
* More advanced detection using machine learning

---

## 📌 Note

This is a beginner-level project and is still evolving. I’ll continue improving it as I learn more about cybersecurity and SOC operations.
