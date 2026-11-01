#!/usr/bin/env python3
"""Fetch Cowrie logs and captured text files from the Pi. The archive comes from an
internet-exposed machine, so only plain files with expected names are accepted, with
size caps. Samples must match their SHA-256 name and contain no NUL bytes; they are
saved without execute permission and are only ever displayed as text."""
import hashlib, os, re, subprocess, sys, tarfile, tempfile
from pathlib import Path

HOST, PORT = os.environ["PI_HOST"], os.environ.get("PI_PORT", "22222")
USER, KEY = os.environ["PI_USER"], os.path.expanduser(os.environ.get("PI_KEY", "~/.ssh/cowrie-logpull"))
OUT = Path(__file__).resolve().parent / "data" / "logs"
SAMPLES = OUT.parent / "samples"
NAME = re.compile(r"^cowrie\.json(\.[0-9_-]+)?$")
SAMPLE = re.compile(r"^[0-9a-f]{64}$")
MAX_TOTAL = 4 * 1024**3
MAX_SAMPLE = 256 * 1024


def save_sample(archive, member, name):
    if member.size > MAX_SAMPLE:
        print(f"skipped oversized sample: {name}", file=sys.stderr)
        return 0
    data = archive.extractfile(member).read(MAX_SAMPLE + 1)
    if hashlib.sha256(data).hexdigest() != name or b"\0" in data:
        print(f"skipped sample that failed checks: {name}", file=sys.stderr)
        return 0
    with tempfile.NamedTemporaryFile(dir=SAMPLES, delete=False) as tmp:
        tmp.write(data)
    os.chmod(tmp.name, 0o644)
    os.replace(tmp.name, SAMPLES / name)
    return 1


def main():
    ssh = ["ssh", "-T", "-i", KEY, "-p", PORT, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
           "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15", f"{USER}@{HOST}"]
    proc = subprocess.Popen(ssh, stdout=subprocess.PIPE)
    total = count = samples = 0
    SAMPLES.mkdir(exist_ok=True)
    try:
        with tarfile.open(fileobj=proc.stdout, mode="r|gz") as archive:
            for member in archive:
                name = member.name.removeprefix("./")
                if member.isfile() and SAMPLE.match(name):
                    samples += save_sample(archive, member, name)
                    continue
                if not member.isfile() or not NAME.match(name):
                    print(f"skipped unexpected archive entry: {name!r}", file=sys.stderr)
                    continue
                total += member.size
                if total > MAX_TOTAL:
                    sys.exit("archive exceeds the size limit; stopping")
                with tempfile.NamedTemporaryFile(dir=OUT, delete=False) as tmp:
                    source = archive.extractfile(member)
                    while chunk := source.read(1024 * 1024):
                        tmp.write(chunk)
                os.chmod(tmp.name, 0o644)
                os.replace(tmp.name, OUT / name)
                count += 1
    finally:
        if proc.stdout:
            proc.stdout.close()
        status = proc.wait()
    if status:
        sys.exit(f"ssh failed with exit code {status}")
    print(f"pulled {count} log files, {total} bytes, {samples} text samples")


if __name__ == "__main__":
    main()
