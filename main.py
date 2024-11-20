import docx
import pandas as pd
import os
from dotenv import load_dotenv
from openai import OpenAI
import tiktoken

# Load environment variables from .env file
load_dotenv()

# Set up the OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def read_docx(file_path):
    """Read and extract text from a .docx file."""
    try:
        doc = docx.Document(file_path)
        text = []
        for paragraph in doc.paragraphs:
            if paragraph.text.strip():  # Only add non-empty lines
                text.append(paragraph.text.strip())
        return "\n".join(text)
    except Exception as e:
        raise FileNotFoundError(f"Error reading the file: {e}")

def count_tokens(text, model="gpt-4"):
    """Count the number of tokens in a text using tiktoken."""
    encoding = tiktoken.encoding_for_model(model)
    return len(encoding.encode(text))

def chunk_text(text, max_chunk_tokens=2000, model="gpt-4"):
    """Split the text into chunks strictly within the max token limit."""
    paragraphs = text.split("\n")
    chunks = []
    current_chunk = []
    current_tokens = 0

    for paragraph in paragraphs:
        paragraph_tokens = count_tokens(paragraph, model=model)
        if current_tokens + paragraph_tokens > max_chunk_tokens:
            chunks.append("\n".join(current_chunk))
            current_chunk = []
            current_tokens = 0
        current_chunk.append(paragraph)
        current_tokens += paragraph_tokens

    if current_chunk:  # Add the last chunk
        chunks.append("\n".join(current_chunk))

    return chunks

def send_to_openai(prompt, model="gpt-4"):
    """Send a cybersecurity-specific prompt to OpenAI API and return the response."""
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert with 25 years of hands-on experience. Extract and analyze log data to identify security incidents, threats, and actionable items."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=800,
            temperature=0.7
        )
        return response.choices[0].message.content
    except Exception as e:
        raise RuntimeError(f"Error interacting with OpenAI API: {str(e)}")

def save_to_csv(data, output_file):
    """Save tabular data to a CSV file."""
    try:
        df = pd.DataFrame(data)
        df.to_csv(output_file, index=False)
        print(f"Data saved to {output_file}")
    except Exception as e:
        raise RuntimeError(f"Error saving data to CSV: {e}")

def main():
    # Step 1: Read the D_S_logs file
    file_path = "D:\wazuh_logs\py\D_S_logs.docx"
    try:
        log_data = read_docx(file_path)
        print("Log data extracted successfully!")
    except FileNotFoundError as e:
        print(e)
        return

    # Step 2: Split the log data into manageable chunks
    max_message_tokens = 8192 - 800  # Reserve 800 tokens for system/prompt/completion
    chunks = chunk_text(log_data, max_chunk_tokens=max_message_tokens)
    print(f"Log data split into {len(chunks)} chunks.")

    # Step 3: Process each chunk
    all_tabular_data = []
    for i, chunk in enumerate(chunks):
        print(f"Processing chunk {i+1}/{len(chunks)} with estimated tokens: {count_tokens(chunk)}")
        prompt = f"""
        Analyze the following log data and extract security-related information. 
        Include the following fields in the tabular output:
        - Threat Type
        - Severity Level
        - Affected Systems
        - Timestamp
        - Description
        - Suggested Mitigation Steps
        
        Here is the log data:
        {chunk}
        """
        try:
            tabular_output = send_to_openai(prompt)
            rows = [row.split("\t") for row in tabular_output.split("\n") if row.strip()]
            headers = rows[0] if all_tabular_data == [] else None  # Use headers only once
            data = rows[1:] if headers else rows  # Exclude headers for subsequent chunks
            all_tabular_data.extend(data)
        except RuntimeError as e:
            print(f"Error processing chunk {i+1}: {e}")

    # Step 4: Save the combined results to a CSV file
    output_file = "cybersecurity_output_3.csv"
    try:
        headers = ["Threat Type", "Severity Level", "Affected Systems", "Timestamp", "Description", "Suggested Mitigation Steps"]
        save_to_csv([dict(zip(headers, row)) for row in all_tabular_data], output_file)
    except Exception as e:
        print(f"Failed to save results: {e}")

if __name__ == "__main__":
    main()