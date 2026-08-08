import os
from pathlib import Path
from dotenv import load_dotenv
from google import genai

# Find .env in the SOCVision-AI project root
env_path = Path(__file__).resolve().parent.parent / ".env"

# Load environment variables
load_dotenv(env_path)

api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    print("ERROR: GEMINI_API_KEY not found")
    exit()

print("API key loaded successfully")

client = genai.Client(api_key=api_key)

response = client.models.generate_content(
    model="gemini-3.1-flash-lite",
    contents="Explain Windows Event ID 4625 in two sentences."
)

print("\nGemini response:")
print(response.text)
