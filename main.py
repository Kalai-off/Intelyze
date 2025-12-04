# backend layer – uploads local files to OpenAI, gets file_ids,
# forwards plain text + ids to the Orchestrator.


import uuid, pathlib, nest_asyncio, os, sys
from pathlib import Path
from dotenv import load_dotenv
from openai import OpenAI
from orchestrator import Orchestrator
import streamlit as st

load_dotenv()

# Try to load from Streamlit secrets first, fallback to environment
try:
    import streamlit as st
    OPENAI_API_KEY = st.secrets.get("openai", {}).get("api_key", os.getenv("OPENAI_API_KEY"))

    # --- load optional sync secrets into environment so sync.remote_sync can use them ---
    aws = st.secrets.get("aws", {}) or {}
    if aws:
        # Only set if not already present to avoid overwriting runtime env
        if aws.get("aws_access_key_id"):
            os.environ.setdefault("AWS_ACCESS_KEY_ID", aws.get("aws_access_key_id"))
        if aws.get("aws_secret_access_key"):
            os.environ.setdefault("AWS_SECRET_ACCESS_KEY", aws.get("aws_secret_access_key"))
        if aws.get("region"):
            os.environ.setdefault("AWS_DEFAULT_REGION", aws.get("region"))
        if aws.get("sync_s3_bucket"):
            os.environ.setdefault("SYNC_S3_BUCKET", aws.get("sync_s3_bucket"))

    rclone = st.secrets.get("rclone", {}) or {}
    if rclone.get("remote_name"):
        os.environ.setdefault("RCLONE_REMOTE", rclone.get("remote_name"))
except (ImportError, KeyError):
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

if not OPENAI_API_KEY:
    raise ValueError("OPENAI_API_KEY not found in .streamlit/secrets.toml or environment variables")

os.environ["OPENAI_API_KEY"] = OPENAI_API_KEY

orchestrator = Orchestrator()
client = OpenAI()

def handle_query(message: str, conv_id: str, local_files: list[str]|None=None):
    file_ids=[]
    for p in local_files or []:
        path=Path(p)
        if not path.exists(): continue
        uploaded=client.files.create(file=path.open("rb"), purpose="assistants")
        file_ids.append(uploaded.id)

    print(message)
    print("-"*10)
    print(file_ids)

    return orchestrator.process_user_query(message, conv_id, file_ids=file_ids)

# CLI quick test
if __name__=="__main__":
    cid=str(uuid.uuid4())
    while True:
        t=input("> "); 
        if t.lower() in {"exit","quit"}: break
        print(handle_query(t, cid))