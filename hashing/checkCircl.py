import hashlib
import requests
import os

def calculate_hash(file_path, algo='sha256'):
    """
    Calculate a hex digest (md5, sha1 or sha256) of the given file.
    """
    h = hashlib.new(algo)
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            h.update(chunk)
    return h.hexdigest()

def check_circl(hash_value):
    """
    Query CIRCL HashLookup for the given hash.
    Returns the JSON metadata if known, else None.
    """
    url = f"https://hashlookup.circl.lu/api/hash/{hash_value}"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            return resp.json()
    except requests.RequestException as e:
        print(f"[!] CIRCL lookup error: {e}")
    return None

def check_file_with_circl(path, algo='sha256'):
    """
    Convenience function: hash the file at `path`, call CIRCL, and report.
    """
    if not os.path.isfile(path):
        print(f"[!] File not found: {path}")
        return None

    h = calculate_hash(path, algo)
    info = check_circl(h)
    if info:
        print(f"[!] CIRCL knows {os.path.basename(path)} ({algo}:{h}):")
        # you can pretty‑print whatever fields you care about
        print(info)
    else:
        print(f"[-] CIRCL did not recognize {os.path.basename(path)} ({algo}:{h})")
    return info
