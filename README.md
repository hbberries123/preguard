## ✨ Features
- **Git-native**: Scans staged files only
  - AWS Access Key IDs (`AKIA...`)
  - AWS Secret Keys
  - Generic key/secret/password/token fields
  - Private key headers (`-----BEGIN PRIVATE KEY-----`)
  - High-entropy strings (configurable threshold)
- skips binaries, images, and ignored paths (`.preguardignore`).
- one liner pre commit hook installation

---

## 🚀 Installation

### Build from source (requires Go 1.22+)
```bash
git clone https://github.com/hbberries123/preguard
cd preguard
go install ./cmd/preguard
```

Now `preguard` should be in your `$PATH`.

---

## 🔧 Setup in a repo

Inside your project:

```bash
preguard install
```

This copies a ready-made script into `.git/hooks/pre-commit`.  
Now every commit will be scanned automatically.

---

## 🧑‍💻 Usage

### Manual scan
```bash
preguard scan
```
Scans your currently staged files. Exits `0` if clean and `1` if secrets are found.

---
