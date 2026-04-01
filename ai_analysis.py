import streamlit as st
from openai import OpenAI

client = OpenAI(api_key=st.secrets["OPENAI_API_KEY"])


def analyze_alert(alert, logs):
    prompt = f"""
You are a SOC (Security Operations Center) analyst.

Analyze the following alert and logs, and provide a structured response with:

1. What happened
2. Why it is suspicious
3. Risk level
4. Recommended action

ALERT:
{alert}

LOGS:
{logs}
"""

    response = client.chat.completions.create(
        model="gpt-4.1-mini",
        messages=[
            {"role": "system", "content": "You are a cybersecurity analyst."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.3
    )

    return response.choices[0].message.content