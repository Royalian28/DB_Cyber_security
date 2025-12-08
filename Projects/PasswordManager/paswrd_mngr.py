import os, json, base64, argparse, getpass, cmd, string, secrets, hashlib
from datetime import datetime, timezone
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import qrcode

# For QR decoding
try:
    from pyzbar.pyzbar import decode as qr_decode
    from PIL import Image
except Exception:
    qr_decode = None
    Image = None

# --------- Helpers ----------
def b64(b: bytes) -> str: return base64.b64encode(b).decode("ascii")
def ub64(s: str) -> bytes: return base64.b64decode(s.encode("ascii"))
def now_iso() -> str: return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
def rand_bytes(n: int) -> bytes: return os.urandom(n)

def derive_master_key(password: str, salt: bytes, time_cost: int, memory_cost_kb: int,
                      parallelism: int, dklen: int = 32) -> bytes:
    return hash_secret_raw(password.encode("utf-8"), salt, time_cost, memory_cost_kb,
                           parallelism, dklen, Type.ID)

def derive_subkeys(master_key: bytes, info: bytes = b"password-manager-v1", length: int = 64):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    out = hkdf.derive(master_key)
    return out[:32], out[32:64]

def wrap_dek_aesgcm(kek: bytes, dek: bytes, associated_data: bytes = b""):
    aesgcm = AESGCM(kek); nonce = rand_bytes(12)
    return nonce, aesgcm.encrypt(nonce, dek, associated_data)

def unwrap_dek_aesgcm(kek: bytes, nonce: bytes, wrapped_ct: bytes, associated_data: bytes = b""):
    return AESGCM(kek).decrypt(nonce, wrapped_ct, associated_data)

# --------- File IO ----------
def read_header(vaultfile: str) -> dict:
    with open(vaultfile, "rb") as f:
        hdr_len_b = f.read(4)
        if len(hdr_len_b) != 4:
            raise ValueError("Invalid vault: missing header length")
        hdr_len = int.from_bytes(hdr_len_b, "big")
        return json.loads(f.read(hdr_len).decode("utf-8"))

def read_records(vaultfile: str, dek: bytes):
    recs = []
    with open(vaultfile, "rb") as f:
        hdr_len = int.from_bytes(f.read(4), "big"); f.seek(4 + hdr_len)
        while True:
            len_bytes = f.read(4)
            if not len_bytes:
                break
            blob_len = int.from_bytes(len_bytes, "big")
            blob = f.read(blob_len)
            if len(blob) != blob_len:
                break
            nonce, ct = blob[:12], blob[12:]
            try:
                rec_json = AESGCM(dek).decrypt(nonce, ct, b"record-v1")
                recs.append(json.loads(rec_json.decode("utf-8")))
            except Exception:
                print("Warning: bad record (tampered or wrong key).")
    return recs

def write_records(vaultfile: str, header: dict, records: list, dek: bytes):
    with open(vaultfile, "wb") as f:
        hdr_bytes = json.dumps(header, indent=2).encode("utf-8")
        f.write(len(hdr_bytes).to_bytes(4, "big")); f.write(hdr_bytes)
        aesgcm = AESGCM(dek)
        for rec in records:
            rec_json = json.dumps(rec).encode("utf-8")
            nonce = rand_bytes(12); ct = aesgcm.encrypt(nonce, rec_json, b"record-v1")
            blob = nonce + ct
            f.write(len(blob).to_bytes(4, "big")); f.write(blob)

# --------- QR helpers ----------
def read_recovery_b64_from_png(path: str) -> str:
    if qr_decode is None or Image is None:
        raise RuntimeError("QR decode dependencies missing. Install: pip install pyzbar pillow  (and apt: sudo apt install libzbar0)")
    data = qr_decode(Image.open(path))
    if not data:
        raise ValueError("No QR found in image")
    return data[0].data.decode()

# -------------- Commands --------------
def cmd_init(args):
    if os.path.exists(args.vaultfile):
        print("Vault exists.")
        return

    kdf_time, kdf_mem, kdf_par = 3, 256*1024, 1
    salt = rand_bytes(16)

    pw = getpass.getpass("Choose master password: ")
    if pw != getpass.getpass("Confirm master password: "):
        print("Mismatch.")
        return

    # Master KEK
    mk = derive_master_key(pw, salt, kdf_time, kdf_mem, kdf_par)
    kek, _ = derive_subkeys(mk, b"pwm-master-keys")

    # Data Encryption Key (DEK)
    dek = rand_bytes(32)

    # Wrap DEK under master KEK
    wrap_nonce, wrapped_dek = wrap_dek_aesgcm(kek, dek, b"header-v1")

    # --- Recovery key flow: generate, hash, QR, and ALSO wrap DEK under recovery key ---
    recovery_key = rand_bytes(32)                     # raw 32-byte recovery key
    recovery_b64 = b64(recovery_key)                  # encode for QR
    recovery_hash = hashlib.sha256(recovery_key).hexdigest()

    # Derive recovery KEK from recovery key (separate HKDF label)
    rec_kek, _ = derive_subkeys(recovery_key, info=b"pwm-recovery-keys", length=64)

    # Wrap same DEK under recovery KEK too (second copy for recovery)
    rec_nonce, wrapped_dek_recovery = wrap_dek_aesgcm(rec_kek, dek, b"header-v1")

    # Save QR image next to vault
    qrfile = args.vaultfile + ".recovery.png"
    qrcode.make(recovery_b64).save(qrfile)
    print(f"[INFO] Recovery QR saved to {qrfile}")

    header = {
        "magic": "PWMV1",
        "version": 1,
        "kdf": "argon2id",
        "kdf_params": {"time": kdf_time, "memory_kib": kdf_mem,
                       "parallelism": kdf_par, "salt_b64": b64(salt)},
        "cipher": "AES-GCM",
        "wrapped_dek_b64": b64(wrapped_dek),
        "wrapped_nonce_b64": b64(wrap_nonce),
        # Recovery metadata + wrapped DEK for recovery path
        "recovery_hash": recovery_hash,
        "wrapped_dek_recovery_b64": b64(wrapped_dek_recovery),
        "wrapped_recovery_nonce_b64": b64(rec_nonce),
        "created_at": now_iso()
    }

    # Create empty vault body
    write_records(args.vaultfile, header, [], dek)
    print("Vault created:", args.vaultfile)

def unlock_and_get_dek(vaultfile: str):
    try:
        hdr = read_header(vaultfile)
    except Exception as e:
        print(f"Failed to read vault: {e}")
        return None, None

    kdfp = hdr["kdf_params"]

    # >>> visible + flushed prompt (fix)
    print("Enter master password: ", end="", flush=True)
    pw = getpass.getpass("")

    mk = derive_master_key(pw, ub64(kdfp["salt_b64"]),
                           int(kdfp["time"]), int(kdfp["memory_kib"]), int(kdfp["parallelism"]))
    kek, _ = derive_subkeys(mk, b"pwm-master-keys")
    try:
        dek = unwrap_dek_aesgcm(kek, ub64(hdr["wrapped_nonce_b64"]),
                                ub64(hdr["wrapped_dek_b64"]), b"header-v1")
        return dek, hdr
    except Exception:
        print("Unlock failed: wrong password or file tampered.")
        return None, None

def cmd_recover(args):
    """
    Recover using a QR image containing the base64 recovery key.
    Usage:
      python paswrd_mngr.py recover <vaultfile> --qr <path/to/recovery.png>
    If --qr is omitted, you will be prompted for a path.
    """
    try:
        header = read_header(args.vaultfile)
    except Exception as e:
        print(f"Failed to read vault: {e}")
        return

    qr_path = args.qr
    if not qr_path:
        qr_path = input("Path to recovery QR image (PNG): ").strip()
    qr_path = os.path.abspath(os.path.expanduser(qr_path))
    if not os.path.exists(qr_path):
        print(f"QR file not found: {qr_path}")
        return

    try:
        rec_b64 = read_recovery_b64_from_png(qr_path).strip()
    except Exception as e:
        print(f"Failed to read QR: {e}")
        return

    # Convert to bytes and verify hash
    try:
        rec_key = ub64(rec_b64)
    except Exception:
        print("Invalid recovery key format in QR.")
        return

    if hashlib.sha256(rec_key).hexdigest() != header.get("recovery_hash"):
        print("Invalid recovery key (hash mismatch).")
        return

    # Derive recovery KEK and unwrap DEK from the recovery-wrapped fields
    rec_kek, _ = derive_subkeys(rec_key, info=b"pwm-recovery-keys", length=64)
    try:
        dek = unwrap_dek_aesgcm(rec_kek,
                                ub64(header["wrapped_recovery_nonce_b64"]),
                                ub64(header["wrapped_dek_recovery_b64"]),
                                associated_data=b"header-v1")
    except Exception:
        print("Failed to unwrap DEK with recovery key (header tampered?).")
        return

    print("[OK] Recovery key accepted.")
    # Let user set NEW master password and re-wrap DEK under it
    new_pw = getpass.getpass("New master password: ")
    if new_pw != getpass.getpass("Confirm: "):
        print("Passwords do not match.")
        return

    kdfp = header["kdf_params"]
    mk = derive_master_key(new_pw,
                           ub64(kdfp["salt_b64"]),
                           int(kdfp["time"]),
                           int(kdfp["memory_kib"]),
                           int(kdfp["parallelism"]))
    kek, _ = derive_subkeys(mk, info=b"pwm-master-keys", length=64)
    wrap_nonce, wrapped_dek = wrap_dek_aesgcm(kek, dek, associated_data=b"header-v1")
    header["wrapped_dek_b64"] = b64(wrapped_dek)
    header["wrapped_nonce_b64"] = b64(wrap_nonce)

    # Keep the recovery-wrapped DEK fields unchanged for future recoveries.
    records = read_records(args.vaultfile, dek)
    write_records(args.vaultfile, header, records, dek)
    print("[SUCCESS] Master password reset. Use your new password to unlock.")

# -------- Shell Class --------
class Shell(cmd.Cmd):
    intro = "Welcome to Password Manager shell. Type help or ? to list commands."
    prompt = "(pwm) "

    def __init__(self, vaultfile, dek, header):
        super().__init__()
        self.vaultfile = vaultfile
        self.dek = dek
        self.header = header
        self.prompt = f"({os.path.basename(vaultfile)}) > "

    def _save(self, records):
        write_records(self.vaultfile, self.header, records, self.dek)

    def do_list(self, arg):
        """List all records"""
        records = read_records(self.vaultfile, self.dek)
        if not records:
            print("No records.")
            return
        for i, rec in enumerate(records, 1):
            print(f"{i}. {rec['service']} ({rec['username']})")

    def do_get(self, arg):
        """Get record by index: get 1"""
        try:
            idx = int(arg.strip()) - 1
        except Exception:
            print("Usage: get <index>")
            return
        records = read_records(self.vaultfile, self.dek)
        if 0 <= idx < len(records):
            rec = records[idx]
            print("Service:", rec["service"])
            print("Username:", rec["username"])
            print("Password:", rec["password"])
            print("Notes:", rec.get("notes", ""))
            print("Created:", rec.get("created_at", ""))
            if "updated" in rec:
                print("Updated:", rec["updated"])
        else:
            print("Invalid index.")

    def do_add(self, arg):
        """Add a new record"""
        service = input("Service: ").strip()
        username = input("Username: ").strip()
        password = getpass.getpass("Password: ").strip()
        notes = input("Notes (optional): ").strip()
        record = {"service": service, "username": username, "password": password,
                  "notes": notes, "created_at": now_iso()}
        records = read_records(self.vaultfile, self.dek)
        records.append(record)
        self._save(records)
        print(f"Record for {service} added.")

    def do_edit(self, arg):
        """Edit an existing record"""
        records = read_records(self.vaultfile, self.dek)
        if not records:
            print("No records.")
            return
        for i, rec in enumerate(records, 1):
            print(f"{i}. {rec['service']} ({rec['username']})")
        try:
            choice = int(input("Enter record number to edit: "))
        except ValueError:
            print("Invalid input.")
            return
        if not (1 <= choice <= len(records)):
            print("Invalid choice.")
            return
        idx = choice - 1
        rec = records[idx]
        new_service  = input(f"Service [{rec['service']}]: ")            or rec['service']
        new_username = input(f"Username [{rec['username']}]: ")          or rec['username']
        new_password = getpass.getpass("Password (blank keep): ")         or rec['password']
        new_notes    = input(f"Notes [{rec.get('notes','')}]: ")          or rec.get('notes','')
        rec.update({"service": new_service, "username": new_username,
                    "password": new_password, "notes": new_notes, "updated": now_iso()})
        records[idx] = rec
        self._save(records)
        print("Record updated successfully.")

    def do_delete(self, arg):
        """Delete record by index: delete 1"""
        try:
            idx = int(arg.strip()) - 1
        except Exception:
            print("Usage: delete <index>")
            return
        records = read_records(self.vaultfile, self.dek)
        if 0 <= idx < len(records):
            rec = records[idx]
            if input(f"Delete {rec['service']} ({rec['username']})? y/N: ").lower() == "y":
                del records[idx]
                self._save(records)
                print("Record deleted.")
        else:
            print("Invalid index.")

    def do_search(self, arg):
        """Search records by keyword"""
        term = arg.strip().lower() if arg.strip() else input("Enter search term: ").strip().lower()
        if not term:
            print("No search term.")
            return
        records = read_records(self.vaultfile, self.dek)
        found = False
        for i, rec in enumerate(records, 1):
            if (term in rec['service'].lower() or
                term in rec['username'].lower() or
                term in rec.get('notes','').lower()):
                print(f"{i}. {rec['service']} ({rec['username']}) - Notes: {rec.get('notes','')}")
                found = True
        if not found:
            print("No matches found.")

    def do_genpass(self, arg):
        """Generate a strong random password. Usage: genpass [length]"""
        try:
            length = int(arg.strip()) if arg.strip() else 16
        except Exception:
            length = 16
        alphabet = string.ascii_letters + string.digits + string.punctuation
        pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
        print(f"Generated password ({length} chars): {pwd}")

    def do_recover(self, arg):
        """(Optional) Reset master password using a recovery QR image"""
        qr_path = arg.strip() or input("Path to recovery QR image (PNG): ").strip()
        qr_path = os.path.abspath(os.path.expanduser(qr_path))
        if not os.path.exists(qr_path):
            print(f"QR file not found: {qr_path}")
            return
        ns = argparse.Namespace(vaultfile=self.vaultfile, qr=qr_path)
        try:
            cmd_recover(ns)
        except SystemExit:
            pass
        # refresh header/DEK after potential reset
        new_dek, new_header = unlock_and_get_dek(self.vaultfile)
        if new_dek:
            self.dek, self.header = new_dek, new_header

    def do_exit(self, arg):
        """Exit shell"""
        print("Exiting.")
        return True

def main():
    p = argparse.ArgumentParser(prog="pwm")
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("init", help="Create a new vault")
    sp.add_argument("vaultfile")

    sp = sub.add_parser("shell", help="Open interactive shell mode")
    sp.add_argument("vaultfile")

    sp = sub.add_parser("recover", help="Recover vault using a QR image")
    sp.add_argument("vaultfile")
    sp.add_argument("--qr", help="Path to recovery QR PNG", default=None)

    args = p.parse_args()
    if args.cmd == "init":
        cmd_init(args)
    elif args.cmd == "shell":
        dek, header = unlock_and_get_dek(args.vaultfile)
        if dek:
            Shell(args.vaultfile, dek, header).cmdloop()
    elif args.cmd == "recover":
        cmd_recover(args)
    else:
        p.print_help()

if __name__ == "__main__":
    main()
