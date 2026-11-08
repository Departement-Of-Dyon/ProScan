"""Exe scanner — pure Python stdlib, no API keys, no third-party libs.

Pick an .exe → SHA-256 hash → we search the web for that exact hash,
then FETCH every result page and grep it for the hash. Any page that
literally contains your file's fingerprint is a place this file exists
online (copy, leak, malware sample list, etc).

Run:  py exe_scanner.py
"""
import hashlib, html, json, re, subprocess, sys, urllib.parse, urllib.request
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog

CHUNK = 1024 * 1024
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36"}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def file_info(path):
    p = Path(path)
    st = p.stat()
    info = {"name": p.name, "size_mb": round(st.st_size / 1048576, 2),
            "modified": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")}
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            f"(Get-AuthenticodeSignature '{path}').Status.ToString()"],
                           capture_output=True, text=True, timeout=15)
        info["signature"] = r.stdout.strip() or "Unknown"
    except Exception:
        info["signature"] = "?"
    return info


def web_search(query, max_results=10):
    """Bing RSS search — clean XML, no key needed. Returns [(title, url)]."""
    try:
        q = urllib.parse.quote(query)
        req = urllib.request.Request(f"https://www.bing.com/search?q={q}&format=rss&setlang=en-us&cc=us",
                                     headers=UA)
        data = urllib.request.urlopen(req, timeout=20).read().decode("utf-8", "replace")
        items = re.findall(r"<item>(.*?)</item>", data, re.S)
        out = []
        for it in items[:max_results]:
            t = re.search(r"<title>(.*?)</title>", it, re.S)
            l = re.search(r"<link>(.*?)</link>", it, re.S)
            if t and l:
                out.append((html.unescape(re.sub(r"<[^>]+>", "", t.group(1))).strip(),
                            html.unescape(l.group(1)).strip()))
        return out
    except Exception:
        return []


def page_contains(url, needle, timeout=12):
    """Fetch a page and check if it literally contains the hash string."""
    try:
        req = urllib.request.Request(url, headers=UA)
        data = urllib.request.urlopen(req, timeout=timeout).read()
        # cap at ~2MB — enough for any mention
        return needle.encode() in data[:2_000_000]
    except Exception:
        return False


def scan_internet(digest):
    """Search hash → fetch result pages → report pages containing the hash."""
    results = web_search(f'"{digest}"')
    if not results:
        results = web_search(digest)
    if not results:
        return {"searched": 0, "found": [], "note": "search engine returned no results for this hash"}
    found = []
    for title, url in results:
        if page_contains(url, digest):
            found.append({"title": title, "url": url})
    return {"searched": len(results), "found": found}


# ---------------- GUI ----------------
class Scanner(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Exe Internet Scanner")
        self.geometry("680x520")
        self.configure(bg="#0f172a")
        self._build()

    def _build(self):
        tk.Label(self, text="Select an .exe — we hunt for it across the web",
                 bg="#0f172a", fg="#e2e8f0", font=("Segoe UI", 15, "bold")).pack(pady=(22, 6))
        tk.Label(self, text="SHA-256 fingerprint → web search → fetch & grep every result",
                 bg="#0f172a", fg="#64748b", font=("Segoe UI", 10)).pack()
        tk.Button(self, text="Choose .exe…", command=self.pick,
                  bg="#2563eb", fg="white", font=("Segoe UI", 11, "bold"),
                  relief="flat", padx=20, pady=8, cursor="hand2").pack(pady=16)
        self.out = tk.Text(self, bg="#020617", fg="#7dd3fc", font=("Consolas", 10),
                           relief="flat", padx=14, pady=12, state="disabled", wrap="word")
        self.out.pack(fill="both", expand=True, padx=24, pady=(0, 22))

    def say(self, t):
        self.out.configure(state="normal")
        self.out.insert("end", t + "\n")
        self.out.see("end")
        self.out.configure(state="disabled")
        self.update_idletasks()

    def pick(self):
        path = filedialog.askopenfilename(
            title="Select exe",
            filetypes=[("Executables", "*.exe *.dll *.scr *.msi *.bat *.ps1"), ("All files", "*.*")])
        if path:
            import threading
            threading.Thread(target=self.scan, args=(path,), daemon=True).start()

    def scan(self, path):
        try:
            self.say(f"\n=== {Path(path).name} ===")
            self.say("hashing file (SHA-256)…")
            digest = sha256(path)
            self.say(f"SHA-256: {digest}")
            for k, v in file_info(path).items():
                self.say(f"  {k}: {v}")
            self.say("\n[Internet scan] searching the web for this exact hash…")
            r = scan_internet(digest)
            self.say(f"  checked {r['searched']} search result(s)")
            if r["found"]:
                self.say(f"\n  ⚠ FOUND on {len(r['found'])} page(s) — this file exists elsewhere online:")
                for f in r["found"]:
                    self.say(f"    • {f['title'][:70]}")
                    self.say(f"      {f['url']}")
            elif r["searched"]:
                self.say("\n  ✓ No result page contains this hash — no public copies found")
            else:
                self.say(f"\n  ? {r.get('note', 'search unavailable')}")
            self.say("\n=== done ===\n")
        except Exception as e:
            self.say(f"ERROR: {e}")


if __name__ == "__main__":
    Scanner().mainloop()
