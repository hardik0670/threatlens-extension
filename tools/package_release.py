"""Build a clean Chrome Web Store ZIP; optionally verify the deployed backend."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-live", action="store_true", help="Fail unless production advertises seller-v2")
    args = parser.parse_args()
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    version = manifest["version"]
    assert re.fullmatch(r"\d+(?:\.\d+){0,3}", version), "Invalid extension version"
    assert manifest["manifest_version"] == 3
    runtime = ["manifest.json", "background.js", "contentScript.js"]
    files = [ROOT / path for path in runtime]
    files += sorted(p for folder in ("popup", "assets") for p in (ROOT / folder).rglob("*") if p.is_file())
    names = {p.relative_to(ROOT).as_posix() for p in files}
    assert all(p.suffix.lower() in {".json", ".js", ".html", ".css", ".png", ".woff2", ".svg"} for p in files)
    assert manifest["background"]["service_worker"] in names
    assert manifest["action"]["default_popup"] in names
    assert all(path in names for path in manifest["icons"].values())
    assert all(path in names for path in manifest["action"]["default_icon"].values())
    assert all(path in names for entry in manifest["content_scripts"] for path in entry["js"])
    bases = [re.search(r'const API_BASE = "([^"]+)"', (ROOT / path).read_text(encoding="utf-8")).group(1)
             for path in ("background.js", "popup/popup.js")]
    assert bases[0] == bases[1] and bases[0] + "/*" in manifest["host_permissions"], "API wiring mismatch"
    assert f"ThreatLens v{version}" in (ROOT / "popup/popup.html").read_text(encoding="utf-8")
    for path in files:
        if path.suffix == ".js":
            subprocess.run(["node", "--check", str(path)], check=True)
        if path.suffix in {".html", ".css"}:
            text = path.read_text(encoding="utf-8")
            references = re.findall(r'(?:src|href)=["\']([^"\']+)["\']', text) if path.suffix == ".html" else re.findall(r'url\(["\']?([^\)"\']+)', text)
            for ref in references:
                if re.match(r"(?:https?:|data:|mailto:|#)", ref):
                    continue
                target = (path.parent / ref.split("?", 1)[0]).resolve()
                assert target.is_relative_to(ROOT) and target.relative_to(ROOT).as_posix() in names, f"Missing packaged asset: {ref}"
    live = None
    if args.check_live:
        with urllib.request.urlopen(bases[0] + "/health", timeout=20) as response:
            live = json.load(response)
        if live.get("extraction_version") != "seller-v2":
            raise SystemExit("Release blocked: deploy the seller-v2 API before uploading the extension.")
    destination = WORKSPACE / "releases"
    destination.mkdir(exist_ok=True)
    stage = destination / f"ThreatLens-{version}"
    stage.mkdir(exist_ok=True)
    existing = {p.relative_to(stage).as_posix() for p in stage.rglob("*") if p.is_file()}
    assert existing <= names, "Unexpected staging files; use a new release directory"
    archive = destination / f"ThreatLens-{version}-Chrome-Web-Store.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
        for source in files:
            relative = source.relative_to(ROOT)
            target = stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            output.write(source, relative.as_posix())
    with zipfile.ZipFile(archive) as output:
        assert output.testzip() is None
        assert set(output.namelist()) == names
        assert json.loads(output.read("manifest.json"))["version"] == version
    report = {"version": version, "api": bases[0], "required_extraction_version": "seller-v2",
              "production_verified": live is not None, "files": len(files), "bytes": archive.stat().st_size,
              "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(), "archive": archive.name}
    (destination / f"ThreatLens-{version}-package.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
