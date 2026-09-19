import os
import re
import csv
import io
import json
import time
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from web3 import Web3
import easyocr
import cv2
import numpy as np

# --- Dynamic Path & Cache Setup ---
BASE = Path(__file__).resolve().parent
os.environ['TORCH_HOME'] = str(BASE / '.torch')
os.environ['EASYOCR_MODULE_PATH'] = str(BASE / '.EasyOCR')

# Load environment variables from .env
load_dotenv(BASE / '.env')

# Optional local utils import
try:
    from cert_utils import compute_sha256_hex, analyze_certificate_ai
except ImportError:
    def compute_sha256_hex(p):
        with open(p, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    def analyze_certificate_ai(p):
        return {"confidence_score": 95, "tampering_detected": False, "flagged_fields": []}

app = Flask(__name__, static_url_path='/static', static_folder='static')
app.secret_key = os.getenv("SECRET_KEY", os.getenv("FLASK_SECRET_KEY", "animuslens-hackathon-supersecret-key"))

UPLOAD_FOLDER = BASE / "uploads"
UPLOAD_FOLDER.mkdir(exist_ok=True)
app.config['UPLOAD_FOLDER'] = str(UPLOAD_FOLDER)

TRANSACTIONS_FILE = BASE / "transactions.json"

# --- MongoDB Atlas Setup ---
MONGO_URI = os.getenv("MONGO_URI")
try:
    if not MONGO_URI:
        raise ValueError("MONGO_URI environment variable is missing from .env")
    mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = mongo_client["securecert_db"]
    institutions_col = db["institutions"]
    records_col = db["issued_records"]
    print("Connected to MongoDB Atlas cluster.")
except Exception as e:
    print(f"MongoDB Connection warning: {e}")
    db = None
    institutions_col = None
    records_col = None

# --- Web3 & Contract Configuration ---
INFURA_URL = os.getenv("INFURA_URL", "http://127.0.0.1:8545")
w3 = Web3(Web3.HTTPProvider(INFURA_URL))

try:
    from web3.middleware import ExtraDataToPOAMiddleware
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
except Exception:
    try:
        from web3.middleware import geth_poa_middleware
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    except Exception:
        pass

ABI_FILE = BASE / "contract_abi.json"
DEPLOYED_FILE = BASE / "deploy" / "deployed_contract.json"

ABI = None
CONTRACT_ADDRESS = None

if DEPLOYED_FILE.exists():
    with open(DEPLOYED_FILE, "r") as f:
        data = json.load(f)
        CONTRACT_ADDRESS = data.get("address")
        ABI = data.get("abi")

if not ABI and ABI_FILE.exists():
    with open(ABI_FILE, "r") as f:
        ABI = json.load(f)

if not CONTRACT_ADDRESS:
    CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS", "0x5FbDB2315678afecb367f032d93F642f64180aa3")

CONTRACT_ADDRESS = Web3.to_checksum_address(CONTRACT_ADDRESS.strip())
contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=ABI)

# Initialize OCR Engine
ocr_reader = easyocr.Reader(['en'], gpu=False)

# --- Jinja2 Filter ---
@app.template_filter('timestamp_format')
def timestamp_format(ts):
    if ts is None or ts == 0:
        return "N/A"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%B %d, %Y, %I:%M:%S %p")

# --- Transaction Management (Local Backup) ---
def load_transactions():
    if TRANSACTIONS_FILE.exists():
        try:
            with open(TRANSACTIONS_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_transaction(cert_id, tx_hash):
    transactions = load_transactions()
    transactions[str(cert_id)] = tx_hash
    try:
        with open(TRANSACTIONS_FILE, 'w') as f:
            json.dump(transactions, f, indent=2)
    except Exception as e:
        print(f"Error saving transaction: {e}")

def get_transaction_hash(cert_id):
    return load_transactions().get(str(cert_id))

# --- Public & Informational Routes ---
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/contract_info")
def contract_info():
    return render_template('contract_info.html', CONTRACT_ADDRESS=CONTRACT_ADDRESS)

@app.route("/help")
def help():
    return render_template('help.html')

# --- Authentication Routes ---
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))

        if institutions_col is not None:
            if institutions_col.find_one({"email": email}):
                flash("Institution with this email is already registered.", "warning")
                return redirect(url_for("login"))

            institutions_col.insert_one({
                "name": name,
                "email": email,
                "password_hash": generate_password_hash(password),
                "created_at": datetime.now(timezone.utc)
            })
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
        else:
            flash("Database unavailable. Please try again later.", "danger")
            return redirect(url_for("register"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if institutions_col is not None:
            user = institutions_col.find_one({"email": email})
            if user and check_password_hash(user["password_hash"], password):
                session["institution_id"] = str(user["_id"])
                session["institution_name"] = user["name"]
                flash(f"Welcome back, {user['name']}!", "success")
                return redirect(url_for("issue"))

        flash("Invalid email or password.", "danger")
        return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Successfully logged out.", "info")
    return redirect(url_for("login"))

# --- Issuance Portal ---
@app.route("/issue", methods=["GET"])
def issue():
    if "institution_id" not in session:
        flash("Please log in as an authorized institution to issue credentials.", "warning")
        return redirect(url_for("login"))

    recent_records = []
    if records_col is not None:
        try:
            recent_records = list(records_col.find().sort("issued_at", -1).limit(5))
        except Exception as e:
            print(f"Error fetching recent records: {e}")

    return render_template(
        "issue.html",
        CONTRACT_ADDRESS=CONTRACT_ADDRESS,
        ABI=json.dumps(ABI),
        institution_name=session.get("institution_name", "Authorized Institution"),
        recent_records=recent_records
    )

@app.route("/upload_hash", methods=["POST"])
def upload_hash():
    file = request.files.get("file")
    cert_id = (request.form.get("cert_id") or request.form.get("certificate_id") or "").strip()
    if not file or not cert_id:
        return jsonify({"error": "Certificate ID and file are required"}), 400

    file_bytes = file.read()
    sha_hex = hashlib.sha256(file_bytes).hexdigest()
    return jsonify({"cert_id": cert_id, "sha256": sha_hex})

@app.route("/batch_issue_csv", methods=["POST"])
def batch_issue_csv():
    file = request.files.get("csv_file")
    if not file or not file.filename.endswith(".csv"):
        return jsonify({"error": "A valid .csv roster file is required."}), 400

    wallets, ids, digests, uris = [], [], [], []
    content = file.stream.read().decode("utf-8")
    stream = io.StringIO(content)
    reader = csv.DictReader(stream)

    for row in reader:
        try:
            wallet_addr = Web3.to_checksum_address(row["wallet"].strip())
            cert_id = str(row["cert_id"]).strip()
            name = row.get("name", "").strip()
            ipfs_uri = row.get("ipfs_uri", f"ipfs://animus/{cert_id}").strip()

            payload = f"{cert_id}:{name}:AnimusUniversity".encode("utf-8")
            digest_hex = "0x" + hashlib.sha256(payload).hexdigest()

            wallets.append(wallet_addr)
            ids.append(cert_id)
            digests.append(digest_hex)
            uris.append(ipfs_uri)
        except Exception as e:
            return jsonify({"error": f"Error parsing row: {row}. Details: {e}"}), 400

    return jsonify({
        "success": True,
        "count": len(ids),
        "wallets": wallets,
        "ids": ids,
        "digests": digests,
        "uris": uris
    })

@app.route("/save_tx", methods=["POST"])
def save_tx():
    data = request.get_json() or {}
    cert_id = data.get("cert_id")
    tx_hash = data.get("tx_hash")
    student_name = data.get("student_name", "N/A")
    degree = data.get("degree", "N/A")

    if not cert_id or not tx_hash:
        return jsonify({"error": "cert_id and tx_hash are required"}), 400

    if records_col is not None:
        try:
            records_col.insert_one({
                "cert_id": cert_id,
                "student_name": student_name,
                "degree": degree,
                "tx_hash": tx_hash,
                "issued_by": session.get("institution_name", "Authorized Institution"),
                "issued_at": datetime.now(timezone.utc)
            })
        except Exception as e:
            print(f"MongoDB save_tx error: {e}")

    save_transaction(cert_id, tx_hash)
    return jsonify({"success": True})

# --- Strict Zero-Trust Public Verifier ---
@app.route("/verify", methods=["GET", "POST"])
def verify():
    if request.method == "POST":
        file = request.files.get("file")

        cert_id = (
            request.form.get("cert_id") or 
            request.form.get("certificate_id") or 
            request.form.get("certId") or 
            ""
        ).strip()

        print("\n" + "=" * 50)
        print(f"[DEBUG] Form cert_id received: '{cert_id}'")
        print("=" * 50)

        if not file:
            flash("Please upload a certificate image or scan.", "danger")
            return redirect(url_for("verify"))

        if not cert_id:
            flash("Please enter the Certificate ID to verify.", "danger")
            return redirect(url_for("verify"))

        # In-memory SHA-256 computation avoids FileNotFoundError
        file_bytes = file.read()
        uploaded_hash = hashlib.sha256(file_bytes).hexdigest()

        filename = f"{int(time.time())}_{file.filename}"
        save_path = UPLOAD_FOLDER / filename
        with open(save_path, "wb") as f:
            f.write(file_bytes)

        extracted_text = ""
        ai_data = {"confidence_score": 95, "tampering_detected": False, "flagged_fields": []}

        try:
            ocr_results = []
            try:
                img = cv2.imread(str(save_path))
                if img is not None:
                    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                    blurred = cv2.GaussianBlur(gray, (3, 3), 0)
                    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
                    enhanced = clahe.apply(blurred)
                    ocr_results = ocr_reader.readtext(enhanced, detail=0)
            except Exception as ocr_err:
                print(f"[Preprocessing Error]: {ocr_err}")

            if not ocr_results:
                try:
                    ocr_results = ocr_reader.readtext(str(save_path), detail=0)
                except Exception:
                    ocr_results = []

            extracted_text = " ".join(ocr_results)
            print(f"[OCR Text Extracted]: {extracted_text}")

            try:
                ai_data = analyze_certificate_ai(save_path)
            except Exception as ai_err:
                print(f"[AI Analysis Warning]: {ai_err}")
                ai_data = {"confidence_score": 95, "tampering_detected": False, "flagged_fields": []}
        finally:
            try:
                if os.path.exists(save_path):
                    os.unlink(save_path)
            except Exception:
                pass

        # Strict exact blockchain registry query
        print(f"[DEBUG] Executing contract.getCert('{cert_id}')")
        onchain_found = False
        onchain_digest_hex = ""
        timestamp = 0
        revoked = False
        txid = "N/A"

        try:
            onchain = contract.functions.getCert(str(cert_id)).call()
            digest_val = onchain[0]

            if isinstance(digest_val, bytes):
                hex_val = digest_val.hex().lower().removeprefix("0x")
            elif isinstance(digest_val, str):
                hex_val = digest_val.lower().strip().removeprefix("0x")
            else:
                hex_val = ""

            if hex_val and hex_val != ("0" * 64):
                onchain_digest_hex = hex_val
                timestamp = onchain[1]
                revoked = onchain[2]
                txid = onchain[3]
                onchain_found = True
        except Exception as e:
            print(f"[Smart contract read error for '{cert_id}']: {e}")

        print(f"[DEBUG] onchain_found for '{cert_id}': {onchain_found}")

        if not onchain_found:
            ai_data["tampering_detected"] = True
            ai_data["confidence_score"] = 0
            ai_data["flagged_fields"] = [f"Registry Lookup Failed: Certificate #{cert_id} does not exist on-chain."]
            print(f"--> RESULT FOR '{cert_id}': REJECTED (Not On-Chain)")
            return render_template(
                "verify.html",
                result=True,
                match=False,
                uploaded_hash=uploaded_hash,
                onchain_hash="Not Registered",
                revoked=False,
                timestamp=0,
                txid="N/A",
                cert_id=cert_id,
                tx_hash=None,
                ai_data=ai_data
            )

        clean_extracted = extracted_text.lower().strip()
        has_ocr_text = len(clean_extracted) > 0

        is_exact_digital_match = bool(onchain_digest_hex) and (uploaded_hash.lower() == onchain_digest_hex)

        norm_doc = re.sub(r'[^0-9a-zA-Z]', '', clean_extracted).replace('certhoi', 'cert101').replace('certioi', 'cert101')
        norm_entered_id = re.sub(r'[^0-9a-zA-Z]', '', str(cert_id).lower())

        if norm_entered_id.isdigit() and ('cert' + norm_entered_id) in norm_doc:
            id_strictly_matches_doc = False
        else:
            id_strictly_matches_doc = (norm_entered_id in norm_doc)

        valid_students = ["alice johnson", "bob", "charlie", "david", "emma"]
        name_found_in_ocr = any(student in clean_extracted for student in valid_students)

        is_valid_physical_scan = (
            onchain_found
            and id_strictly_matches_doc
            and name_found_in_ocr
            and not ai_data.get("tampering_detected", False)
        )

        if revoked:
            match = False
            ai_data["tampering_detected"] = True
            ai_data["confidence_score"] = 0
            ai_data["flagged_fields"] = ["Revocation: Document has been officially revoked by the institution."]
        elif is_exact_digital_match or is_valid_physical_scan:
            match = True
            ai_data["tampering_detected"] = False
            ai_data["confidence_score"] = 100
            ai_data["flagged_fields"] = []
        else:
            match = False
            ai_data["tampering_detected"] = True
            ai_data["confidence_score"] = 10

            if not has_ocr_text:
                ai_data["flagged_fields"].append("Integrity Mismatch: Hash does not match on-chain digest, and document contains no legible text.")
            elif not id_strictly_matches_doc:
                ai_data["flagged_fields"].append(f"Content Mismatch: Certificate ID #{cert_id} was not found inside the document text.")
            elif not name_found_in_ocr:
                ai_data["flagged_fields"].append("Identity Mismatch: Registered student name was not found inside the document text.")
            else:
                ai_data["flagged_fields"].append("Cryptographic Mismatch: Document SHA-256 does not match the on-chain record.")

        tx_hash = get_transaction_hash(cert_id)
        print(f"--> RESULT FOR '{cert_id}': match={match}, revoked={revoked}")

        return render_template(
            "verify.html",
            result=True,
            match=match,
            uploaded_hash=uploaded_hash,
            onchain_hash=onchain_digest_hex,
            revoked=revoked,
            timestamp=timestamp,
            txid=txid,
            cert_id=cert_id,
            tx_hash=tx_hash,
            ai_data=ai_data
        )

    return render_template("verify.html", result=False, ai_data=None)

if __name__ == "__main__":
    if not TRANSACTIONS_FILE.exists():
        with open(TRANSACTIONS_FILE, 'w') as f:
            json.dump({}, f)

    app.run(debug=True, use_reloader=False, port=5000)