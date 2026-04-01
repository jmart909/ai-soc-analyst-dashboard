import os
from dotenv import load_dotenv
from openai import OpenAI

# Load API key from .env
load_dotenv()
api_key = os.getenv("OPENAI_API_KEY")

client = OpenAI(api_key=api_key)


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