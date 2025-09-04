# 🔐 Python Password Manager

A lightweight command-line password manager built in Python, secured with:

- Argon2id KDF for deriving master keys from your password  
- AES-256 GCM (AEAD) for record encryption  
- HKDF key separation for KEK/DEK management  
- QR-based recovery option (offline recovery without cloud storage)  
- Interactive shell mode for adding, listing, searching, editing, and deleting records  

This is an educational project that demonstrates how modern password managers can be built with strong crypto and simple UX.

---

# Features

✅ Create a new encrypted password vault  
✅ Add / List / Get / Edit / Delete records  
✅ Full interactive shell mode  
✅ Search and filter entries  
✅ Generate strong random passwords  
✅ Master password protection (Argon2id)  
✅ Recovery mechanism using offline QR codes  
✅ All records encrypted with AES-GCM (authenticated encryption)  
✅ Cross-platform (Linux, Mac, Windows)  

---

# Installation

### 1. Clone the repo
bash
git clone https://github.com/yourusername/password-manager.git
cd password-manager

### 2. Create a virtual environment (recommended)

bash
python3 -m venv env
source env/bin/activate   # Linux/Mac
env\Scripts\activate      # Windows

### 3. Install dependencies

bash
pip install -r requirements.txt


If you want QR recovery support:

bash
pip install pillow pyzbar qrcode
sudo apt install libzbar0   # Linux only
---

# Dependencies

* [argon2-cffi](https://pypi.org/project/argon2-cffi/) (Argon2id KDF)
* [cryptography](https://pypi.org/project/cryptography/) (AES-GCM, HKDF)
* [qrcode](https://pypi.org/project/qrcode/) (for QR generation)
* [pillow](https://pypi.org/project/Pillow/) + [pyzbar](https://pypi.org/project/pyzbar/) (for QR decoding)

---

# Usage

### 1. Initialize a vault

bash
python paswrd_mngr.py init myvault.pwm

* Choose a master password (Argon2id derived).
* Generates a recovery QR: `myvault.pwm.recovery.png`.
* Store this QR  offline and securely (USB, printed copy).

---

### 2. Open the shell

bash
python paswrd_mngr.py shell <Your_VaultName.pwm>

Available commands inside shell:

list            - List all records
get <index>     - Show details of a record
add             - Add a new record
edit            - Edit an existing record
delete <index>  - Delete a record
search <term>   - Search records
genpass [len]   - Generate strong password
recover [file]  - Reset master password via QR
exit            - Exit the shell

---

### 3. Recover vault (if master password is lost)

bash
python paswrd_mngr.py recover myvault.pwm --qr myvault.pwm.recovery.png

* Scans the QR to verify recovery key
* Lets you set a new master password
* Your records remain intact

---

# Security Design

* Master Password → Argon2id → Master Key (MK)
* MK → HKDF → Key Encryption Key (KEK) + session key
* Random Data Encryption Key (DEK) generated once per vault
* DEK wrapped under KEK using AES-GCM
* Each record encrypted with DEK + fresh random nonce
* Recovery Key (random 32 bytes) also wraps DEK (via QR mechanism)

Zero-knowledge:
If you lose both master password & recovery QR, your data is unrecoverable.

---

## ⚠️ Disclaimer

This project is for educational and personal use only.
While it uses strong cryptographic primitives, it has not undergone professional security audits.

Do not use it as your only password manager for sensitive accounts without understanding the risks.

---

# Contributing

Pull requests are welcome!
Ideas for improvement:

* Browser extension support
* Cloud sync (with end-to-end encryption)
* Multi-factor authentication

---

# Demo (Screenshots)


<img width="1920" height="824" alt="Screenshot (145)" src="https://github.com/user-attachments/assets/59b0bcd2-fd84-46c3-905a-afd43c98252f" />
