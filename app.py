# Intelyze Streamlit front-end
# ---------------------------------------------------------------------------
import json, os, uuid, shutil, pathlib, re, hashlib, secrets, hmac
from datetime import datetime, UTC
import sys
import threading

import streamlit as st
import plotly.graph_objects as go
import plotly.io as pio
from main import handle_query                            # backend bridge

# Load TOML based on Python version
if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib



# main.py  (only lines you must add / change)
import asyncio

# ─── ensure an event loop exists even in Streamlit’s ScriptThread ───
try:
    asyncio.get_running_loop()
except RuntimeError:                # no loop; create one & set it
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    
# ---------- paths -----------------------------------------------------------
BASE = pathlib.Path(__file__).parent
CONFIG_FILE = BASE / "config" / "config.toml"

def _load_app_config():
    """Load application configuration from config/config.toml."""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "rb") as f:
            return tomllib.load(f)
    return {"auth": {"allowed_emails": []}}

SESS_DIR  = BASE / "session_management";  SESS_DIR.mkdir(exist_ok=True)
UPLOADS   = BASE / "uploads" / "files";   UPLOADS.mkdir(parents=True, exist_ok=True)

SESSION_FILE = SESS_DIR / "session.json"
CONTENT_FILE = SESS_DIR / "user_chat.json"
USER_FILE    = SESS_DIR / "user.json"
CONFIG_DIR  = BASE / "config";  CONFIG_DIR.mkdir(exist_ok=True)
ALLOWED_EMAILS_FILE = CONFIG_DIR / "allowed_emails.json"

def _load_config():
    """Load configuration from TOML file."""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "rb") as f:
            return tomllib.load(f)
    return {"auth": {"allowed_emails": []}}

# ---------- robust JSON helpers --------------------------------------------
def _load(p: pathlib.Path, default):
    try:
        if p.exists() and p.stat().st_size > 0:
            return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        pass
    return default

def _save(p: pathlib.Path, data):
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    # Background sync for Streamlit Cloud / remote persistence
    try:
        path_str = str(p).replace("\\", "/")
        should_sync = False
        sync_target = None
        
        # Determine what to sync
        if "/session_management/" in path_str:
            should_sync = True
            sync_target = SESS_DIR  # Sync entire session_management folder
        elif "/uploads/" in path_str:
            should_sync = True
            sync_target = UPLOADS.parent  # Sync uploads folder
        elif p.name == "app_log.csv":
            should_sync = True
            sync_target = p  # Sync just the log file

        if should_sync and sync_target:
            def _bg_sync(path_to_sync, remote_path):
                try:
                    from sync.remote_sync import sync_path
                    sync_path(path_to_sync, remote_subpath=remote_path)
                except Exception as e:
                    print("background sync failed:", e)

            # Determine remote path based on folder name
            if sync_target == SESS_DIR:
                remote_path = "session_management"
            elif sync_target == UPLOADS.parent:
                remote_path = "uploads"
            else:
                remote_path = "app_log.csv"

            t = threading.Thread(target=_bg_sync, args=(sync_target, remote_path), daemon=True)
            t.start()
    except Exception:
        pass

# ---------- auth + session helpers -----------------------------------------
def auth(user, pwd):
    rec = find_user(user)
    if not rec:
        return False
    # If hashed password exists, verify with PBKDF2-SHA256
    if "password_hash" in rec:
        return verify_password(pwd, rec["password_hash"])
    # Legacy plaintext path: accept once and migrate to hashed
    if rec.get("password") == pwd:
        rec["password_hash"] = hash_password(pwd)
        rec.pop("password", None)
        rec.setdefault("name", derive_name_from_username(rec.get("username", "")))
        update_user(rec)
        return True
    return False

def uid(name):
    for u in _load(USER_FILE, []):
        if u["username"] == name:
            return u.get("user_id", name)
    return name

def list_sessions(user_id):
    return [s for s in _load(SESSION_FILE, []) if s["user_id"]==user_id and s.get("platform")=="web_app"]

def create_session(user_id):
    sid = str(uuid.uuid4()); now=datetime.now(UTC).isoformat()
    s = _load(SESSION_FILE, []); s.append({"session_id":sid,"user_id":user_id,
        "platform":"web_app","created_timestamp":now,"update_timestamp":now}); _save(SESSION_FILE,s)
    c = _load(CONTENT_FILE, []); c.append({"session_id":sid,"username":user_id,"messages":[]}); _save(CONTENT_FILE,c)
    return sid

def _touch(sid):
    s=_load(SESSION_FILE,[])
    for x in s:
        if x["session_id"]==sid: x["update_timestamp"]=datetime.now(UTC).isoformat(); break
    _save(SESSION_FILE,s)

def _history(sid):
    for c in _load(CONTENT_FILE,[]): 
        if c["session_id"]==sid: return c["messages"]
    return []

def _store(sid, role, content):
    convs=_load(CONTENT_FILE,[])
    for c in convs:
        if c["session_id"]==sid:
            c["messages"].append({"role":role,"content":content,
                                  "timestamp":datetime.now(UTC).isoformat()})
            break
    _save(CONTENT_FILE,convs)

def set_expired(sid, flag=True):
    """Mark a chat session as expired (persisted in SESSION_FILE)."""
    s = _load(SESSION_FILE, [])
    for x in s:
        if x["session_id"] == sid:
            if flag:
                x["expired"] = True
            else:
                x.pop("expired", None)
            x["update_timestamp"] = datetime.now(UTC).isoformat()
            break
    _save(SESSION_FILE, s)

def is_expired(sid):
    """Check if a chat session is marked expired."""
    for x in _load(SESSION_FILE, []):
        if x["session_id"] == sid:
            return bool(x.get("expired"))
    return False


# ---------- sign-up helpers (email validation + persistence) ----------
def normalize_email(email: str) -> str:
    return (email or "").strip().lower()

def _load_allowed_emails():
    """Load allowed emails from config/config.toml."""
    config = _load_app_config()
    emails = config.get("auth", {}).get("allowed_emails", [])
    try:
        return {normalize_email(e) for e in emails if isinstance(e, str)}
    except Exception:
        return set()

def is_email_allowed(email: str) -> bool:
    """
    Returns True if email is in the allowlist.
    If allowlist is empty, denies all emails (feature enforced).
    """
    allowed = _load_allowed_emails()
    if not allowed:
        return False
    return normalize_email(email) in allowed

def load_users():
    return _load(USER_FILE, [])

def save_users(users):
    _save(USER_FILE, users)

def find_user(username_input: str):
    target = (username_input or "").strip().lower()
    for u in load_users():
        if (u.get("username", "")).strip().lower() == target:
            return u
    return None

def user_exists(username: str) -> bool:
    return find_user(username) is not None

def derive_name_from_username(username: str) -> str:
    s = (username or "").strip()
    if "@" in s:
        s = s.split("@", 1)[0]
        s = s.replace(".", " ").replace("_", " ")
    return s.title() if s else "User"

def hash_password(password: str, iterations: int = 100_000) -> str:
    salt_hex = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"), bytes.fromhex(salt_hex), iterations).hex()
    return f"pbkdf2_sha256${iterations}${salt_hex}${dk}"

def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iter_s, salt_hex, hash_hex = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iter_s)
        test = hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"), bytes.fromhex(salt_hex), iterations).hex()
        return hmac.compare_digest(test, hash_hex)
    except Exception:
        return False

def update_user(updated_rec: dict) -> None:
    users = load_users()
    uname = (updated_rec.get("username", "")).strip().lower()
    for i, u in enumerate(users):
        if (u.get("username", "")).strip().lower() == uname:
            users[i] = updated_rec
            break
    else:
        users.append(updated_rec)
    save_users(users)

def add_user(username: str, name: str, password: str) -> None:
    email = normalize_email(username)
    rec = {
        "username": email,
        "name": (name or "").strip(),
        "password_hash": hash_password(password),
    }
    users = load_users()
    users.append(rec)
    save_users(users)

def get_display_name(username_input: str) -> str:
    rec = find_user(username_input)
    if rec and rec.get("name"):
        return rec["name"]
    return derive_name_from_username(username_input)

# ---------- figure helpers --------------------------------------------------
def _fig_cache(fig): return {"fig_json":fig.to_json()} if isinstance(fig,go.Figure) else fig
def _rep_fig(o):
    if isinstance(o,go.Figure): return _fig_cache(o)
    if isinstance(o,list): return [_rep_fig(x) for x in o]
    if isinstance(o,dict): return {k:_rep_fig(v) for k,v in o.items()}
    return o
def _render(o):
    if isinstance(o,dict) and "fig_json" in o:
        st.plotly_chart(pio.from_json(o["fig_json"]), use_container_width=True)
    elif isinstance(o,(list,tuple)): [ _render(x) for x in o ]
    else: st.write(o)

# ---------- unwrap ChatInputValue ------------------------------------------
# ---------- unwrap ChatInputValue ------------------------------------------
def _unwrap(val):
    """
    Returns (text:str, files:list[UploadedFile])
    Handles every form Streamlit might hand us:
       • the new ChatInputValue
       • a plain str (old API, no attachments)
       • the legacy tuple  (str, files)
    """
    if val is None:
        return "", []

    # 1️⃣  The current ChatInputValue object
    if hasattr(val, "text") and (hasattr(val, "files") or isinstance(val, dict)):
        files = val["files"] if isinstance(val, dict) else val.files
        return val.text or "", list(files or [])

    # 2️⃣  Legacy tuple (pre-1.34.0)
    if isinstance(val, tuple) and len(val) == 2:
        msg, files = val
        return msg or "", list(files or [])

    # 3️⃣  Just a string (no attachments)
    if isinstance(val, str):
        return val, []

    # 4️⃣  Fallback: stringify anything else
    return str(val), []

# ---------- Streamlit page --------------------------------------------------
st.set_page_config(page_title="Intelyze", page_icon=str(BASE / "assets" / "intelyze.ico"))
# Lightweight style to blend the brand and improve visuals
st.markdown("""
    <style>
    :root { --brand:#115E6E; --brand-accent:#03AEAA; --brand-dark:#0D4956; }

    /* Headings and global accents */
    h1, h2, h3 { color: var(--brand); }

    /* Sidebar: prevent whole sidebar from scrolling; only chats list will scroll */
    section[data-testid="stSidebar"] { position: relative !important; overflow: hidden !important; }
    section[data-testid="stSidebar"] .block-container { padding-bottom: 80px; overflow: visible; }

    /* Small divider bar used between Logout and New chat */
    .mini-divider {
        height: 6px;
        margin: .5rem 0 .75rem 0;
        background: linear-gradient(90deg, rgba(17,94,110,0.25), rgba(3,174,170,0.5), rgba(17,94,110,0.25));
        border-radius: 3px;
    }

    .welcome-card {
        padding: 1rem 1.25rem;
        border: 1px solid rgba(17,94,110,0.15);
        border-radius: 12px;
        background: linear-gradient(180deg, rgba(17,94,110,0.10), rgba(3,174,170,0.06));
        margin: .25rem 0 0.75rem 0;
    }
    .stButton>button {
        background: var(--brand);
        color: #fff;
        border-radius: 8px;
        border: none;
        padding: 0.5rem 1rem;
        font-weight: 600;
    }
    .stButton>button:hover { background: var(--brand-dark); }
    .stButton>button:disabled { background: #d6f4f3; color: #0b3f4a; border: 1px solid #8bdedd; }
    .stSidebar .stButton>button { width: 100%; }

    /* Scroll only the chats list area */
    #chats-scroll {
        max-height: calc(100vh - 220px); /* leave room for header and fixed logout */
        overflow-y: auto;
        padding-right: 6px; /* keep native scrollbar from overlapping */
    }

    /* Typing bubble while processing */
    .typing-bubble {
        display: inline-block;
        padding: 6px 10px;
        background: rgba(3,174,170,0.12);
        border: 1px solid rgba(17,94,110,0.15);
        color: #0D4956;
        border-radius: 16px;
        font-size: 0.9rem;
    }
    .typing-dot {
        display: inline-block;
        width: 6px;
        height: 6px;
        margin-left: 3px;
        background: var(--brand-accent);
        border-radius: 50%;
        animation: typing-bounce 1.2s infinite ease-in-out;
        vertical-align: middle;
    }
    .typing-dot:nth-child(2) { animation-delay: 0.15s; }
    .typing-dot:nth-child(3) { animation-delay: 0.3s; }
    @keyframes typing-bounce {
        0%, 80%, 100% { transform: scale(0.5); opacity: .5; }
        40% { transform: scale(1.0); opacity: 1; }
    }

    /* Softer styling for forms (affects Login form too) */
    .stForm {
        padding: 1rem 1.25rem;
        border: 1px solid rgba(17,94,110,0.12);
        border-radius: 12px;
        background: linear-gradient(180deg, rgba(17,94,110,0.06), rgba(3,174,170,0.04));
    }

    /* Inputs focus accent */
    div[data-baseweb="input"] input { border-radius: 8px; }
    div[data-baseweb="input"] input:focus {
        box-shadow: 0 0 0 1px var(--brand-accent) !important;
        border-color: var(--brand-accent) !important;
    }
    /* Classy login enhancements */
    .stApp { 
        background: radial-gradient(1200px 400px at 50% -10%, rgba(3,174,170,0.08), transparent 60%),
                    linear-gradient(180deg, rgba(17,94,110,0.02), rgba(3,174,170,0.02));
    }
    .stForm {
        box-shadow: 0 6px 22px rgba(13,73,86,0.12);
        backdrop-filter: blur(2px);
    }
    .auth-hero { text-align:center; margin: .25rem 0 1rem 0; color: var(--brand-dark); }
    .auth-hero h2 { margin: .25rem 0 .25rem 0; }
    .auth-footer { text-align:center; color:#0D4956; font-size: 0.92rem; margin-top: .5rem; }
    div[data-baseweb="tab"] { font-weight: 600; }

    </style>
""", unsafe_allow_html=True)
for k,v in [("authenticated",False),("username",None),("session_id",None)]: st.session_state.setdefault(k,v)
st.session_state.setdefault("welcome_dismissed", False)
st.session_state.setdefault("prefer_signup", False)

# ---- LOGIN ----------------------------------------------------------------
if not st.session_state.authenticated:
    st.title("Intelyze")
    st.markdown(f'''
<div class="auth-hero">
  <h2>Welcome</h2>
  <p style="margin:0">Sign in with your email to continue</p>
</div>
''', unsafe_allow_html=True)
    prefer_signup = st.session_state.get("prefer_signup", False)
    if prefer_signup:
        tab_signup, tab_login = st.tabs(["Sign up", "Login"])
    else:
        tab_login, tab_signup = st.tabs(["Login", "Sign up"])

    with tab_login:
        with st.form("login"):
            u = st.text_input("Username or email")
            p = st.text_input("Password", type="password")
            st.session_state["prefer_signup"] = False
            if st.form_submit_button("Log in"):
                if not is_email_allowed(u):
                    st.error("❌ This email is not on the allowed list. Contact support.")
                elif auth(u, p):
                    rec = find_user(u)
                    uname = rec["username"] if rec else (u or "")
                    st.session_state.update(authenticated=True, username=uname)
                    st.session_state["display_name"] = rec.get("name") if rec else derive_name_from_username(uname)
                    
                    st.rerun()
                else:
                    st.error("Wrong credentials")

    # Login footer CTA: New user? Sign up
    st.markdown('<div class="auth-footer">New user? <strong>Sign up</strong> to create your account.</div>', unsafe_allow_html=True)
            

    with tab_signup:
        st.markdown("Use your email to create an account. Only emails in the allowed list can sign up.")
        with st.form("signup"):
            full_name = st.text_input("Full name")
            email = st.text_input("Email")
            pwd = st.text_input("Password", type="password")
            confirm = st.text_input("Confirm password", type="password")
            create = st.form_submit_button("Create account")
            if create:
                email_norm = normalize_email(email)
                name_norm = (full_name or "").strip()
                if not name_norm:
                    st.error("Name cannot be empty.")
                elif user_exists(email_norm):
                    st.error("An account with this email already exists.")
                elif not is_email_allowed(email_norm):
                    st.error("❌ This email is not on the allowed list. Contact support.")
                elif not pwd:
                    st.error("Password cannot be empty.")
                elif pwd != confirm:
                    st.error("Passwords do not match.")
                else:
                    add_user(email_norm, name_norm, pwd)
                    st.success("Account created. You are now signed in.")
                    st.session_state.update(authenticated=True, username=email_norm)
                    st.session_state["display_name"] = name_norm
                    st.session_state["prefer_signup"] = False
                    st.rerun()

    st.stop()

# ---- sidebar --------------------------------------------------------------
UID = uid(st.session_state.username)
DISPLAY_NAME = st.session_state.get("display_name") or get_display_name(st.session_state.username)
st.sidebar.title(f"Hi {DISPLAY_NAME}")
st.sidebar.image(str(BASE / "assets" / "intelyze.ico"), width=32)

# Logout just below greeting
if st.sidebar.button("Log out"):
    for k in ["authenticated","username","session_id","welcome_dismissed"]: st.session_state.pop(k,None)
    st.rerun()

# Small divider bar
st.sidebar.markdown('<div class="mini-divider"></div>', unsafe_allow_html=True)

# New chat below the divider
if st.sidebar.button("New chat"):
    st.session_state.session_id = None
    st.session_state.welcome_dismissed = True
    st.rerun()

st.sidebar.markdown('<div class="mini-divider"></div>', unsafe_allow_html=True)


sessions = list_sessions(UID)
st.sidebar.markdown('<div id="chats-scroll">', unsafe_allow_html=True)
st.sidebar.subheader("Chats")
if sessions:
    # Sort by most recent first (descending update_timestamp)
    sessions_sorted = sorted(
        sessions,
        key=lambda s: s.get("update_timestamp", ""),
        reverse=True,
    )
    current = st.session_state.session_id
    # Show a button per session (label = updated timestamp)
    for s in sessions_sorted:
        sid = s["session_id"]
        label = s.get("update_timestamp", "")[:19].replace("T"," ")
        if sid == current:
            st.sidebar.button(f"• {label}", key=f"chat_btn_{sid}", disabled=True)
        else:
            if st.sidebar.button(label, key=f"chat_btn_{sid}"):
                st.session_state.session_id = sid
                st.rerun()
else:
    st.sidebar.info("No previous chats")
    st.session_state.session_id = None

st.sidebar.markdown('</div>', unsafe_allow_html=True)



# ---- header ---------------------------------------------------------------
with st.container():
    _c1, _c2 = st.columns([0.08, 0.92])
    with _c1:
        st.image(str(BASE / "assets" / "intelyze.ico"), width=36)
    with _c2:
        st.markdown("## Intelyze")

# ---- chat input (collect first, so welcome can hide on submit) ----------
# compute expired flag and optionally show warning
EXPIRED = is_expired(st.session_state.session_id)
if EXPIRED:
    st.warning("This chat session has expired. Start a New chat to continue.")

raw = st.chat_input("Type here …", accept_file="multiple",file_type=["csv", "xlsx"], disabled=EXPIRED)

# ---- welcome panel (simple) ----------
if st.session_state.session_id is None and not st.session_state.get("welcome_dismissed", False) and not raw:
    with st.container():
        st.markdown(f'''
<div class="welcome-card">
  <h3 style="margin-top:0">Welcome, {DISPLAY_NAME}!</h3>
  <p>Click <b>Start New Chat</b> to begin.</p>
</div>
''', unsafe_allow_html=True)

        if st.button("Start New Chat", key="welcome_new_chat"):
            # Do not create a session yet; it will be created on first message
            st.session_state.welcome_dismissed = True
            st.rerun()

# ---- render history -------------------------------------------------------
for m in _history(st.session_state.session_id):
    _role = "user" if m["role"]=="user" else "assistant"
    _avatar = "🧑" if _role=="user" else str(BASE / "assets" / "intelyze.ico")
    with st.chat_message(_role, avatar=_avatar):
        _render(m["content"])

# ---- chat input -----------------------------------------------------------
# (computed above)
if raw:
    text, files = _unwrap(raw)

    if st.session_state.session_id is None:
        st.session_state.session_id = create_session(UID)
        st.session_state.welcome_dismissed = True

    saved=[]
    for f in files:
        dest = UPLOADS / st.session_state.session_id / f"{uuid.uuid4()}_{f.name}"
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open("wb") as dst: shutil.copyfileobj(f, dst)
        saved.append(str(dest))

        # Trigger background sync for the single file (best-effort)
        try:
            def _bg_sync_file(file_path):
                try:
                    from sync.remote_sync import sync_path
                    # Compute remote subpath relative to BASE so remote layout matches local
                    p = pathlib.Path(file_path)
                    remote_sub = p.relative_to(BASE).as_posix()
                    sync_path(str(p), remote_subpath=remote_sub)
                except Exception as _e:
                    print("background file sync failed:", _e)

            t = threading.Thread(target=_bg_sync_file, args=(str(dest),), daemon=True)
            t.start()
        except Exception:
            pass

    with st.chat_message("user", avatar="🧑"):
        st.write(text if text else "📎 file upload")
        if saved: st.markdown("**Attachments:** "+", ".join(pathlib.Path(p).name for p in saved))

    _store(st.session_state.session_id,"user",text); _touch(st.session_state.session_id)

    # Ephemeral typing bubble while processing
    with st.chat_message("assistant", avatar=str(BASE / "assets" / "intelyze.ico")):
        _typing = st.empty()
        _typing.markdown('<div class="typing-bubble">Thinking<span class="typing-dot"></span><span class="typing-dot"></span><span class="typing-dot"></span></div>', unsafe_allow_html=True)

    try:
        reply = handle_query(text, st.session_state.session_id, local_files=saved)
        _expired_now = False
    except Exception as e:
        _msg = str(e)
        if any(k in _msg.lower() for k in ("container is expired", "container expired", "expired container")):
            # Mark this chat as expired and inform the user
            set_expired(st.session_state.session_id, True)
            reply = {"type":"text","data":"⚠️ Session expired. Please start a New chat to continue."}
            _expired_now = True
        else:
            reply = {"type":"text","data":f"⚠️ {e}"}
            _expired_now = False

    payload = _rep_fig(reply.get("data") if isinstance(reply,dict) else reply)
    _store(st.session_state.session_id,"assistant",payload); _touch(st.session_state.session_id)
    if _expired_now:
        # Rerun to immediately disable the input for this chat
        st.rerun()
    # Remove the typing bubble and render final reply
    try:
        _typing.empty()
    except Exception:
        pass
    with st.chat_message("assistant", avatar=str(BASE / "assets" / "intelyze.ico")): _render(payload)
    # Rerun to refresh sidebar selection and state after a successful message
    st.rerun()
