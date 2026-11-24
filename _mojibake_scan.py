"""Find UTF-8 text that was decoded as CP1251 (mojibake) in repo text files."""
from pathlib import Path
import re

ROOT = Path(".")
EXT = {".py", ".js", ".html", ".css", ".md", ".json", ".service"}
pat = re.compile(r"[^\x00-\x7F]+")
found = []
for path in ROOT.rglob("*"):
    if not path.is_file() or path.suffix not in EXT:
        continue
    if any(part in {".git", "venv", "node_modules", ".hallmark"} for part in path.parts):
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    for lineno, line in enumerate(text.splitlines(), 1):
        for run in pat.findall(line):
            try:
                decoded = run.encode("cp1251").decode("utf-8")
            except (UnicodeEncodeError, UnicodeDecodeError):
                continue
            if decoded == run:
                continue
            if re.search(r"[А-Яа-яЁё]", decoded) and re.search(r"[РСвЂЎЃ‚ѓ„…†‡€‰™]", run):
                found.append((str(path), lineno, run, decoded))

for path, lineno, run, decoded in found:
    print(f"{path}:{lineno}: {run!r} -> {decoded!r}")
print("TOTAL", len(found))
