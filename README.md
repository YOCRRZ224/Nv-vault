# NV Files (Nautilus Edition)

A native GNOME (GTK4 + Libadwaita) encrypted file gallery using `.nv` envelope-encrypted containers.

## Cryptographic Specification (Unchanged)
- **Password Derivation (`P.Key`):** Argon2id (`time_cost=3`, `memory_cost=64MB`, `parallelism=4`, 16-byte random salt). Never stores plaintext passwords or plain SHA-256 hashes.
- **Vault Master Key (`M.Key`):** 256-bit key generated once on setup, encrypted by `P.Key` via AES-256-GCM in `vault_config.json`. Displayed once on creation and can be imported in **Settings -> Migrate M.Key** when switching devices.
- **Individual File Key (`I.Key`) & `.nv` Container:** Every converted file gets a unique 256-bit `I.Key` and is encrypted with AES-256-GCM. The `.nv` metadata header stores `wrapped_ikey` (`I.Key` encrypted by `M.Key`) and binds the entire header as Additional Authenticated Data (AAD).

## Project Structure
```text
nv-vault-nautilus/
├── main.py                  # Application entry point
├── requirements.txt         # Python dependencies
└── nv_vault/
    ├── __init__.py
    ├── crypto.py            # AES-256-GCM + Argon2id + .nv binary parser
    ├── vault.py             # Vault directory, M.Key lifecycle, migration
    └── ui/
        ├── __init__.py
        ├── styles.py        # Native Libadwaita + Nautilus tile CSS
        ├── dialogs.py       # Key Copy modal, Settings M.Key migration, Shared I.Key viewer
        └── window.py        # Nautilus NavigationSplitView + Grid/List + Inspector Pane
```

## Running on Debian / Ubuntu / Termux proot
```bash
sudo apt update && sudo apt install -y python3-gi python3-gi-cairo gir1.2-gtk-4.0 gir1.2-adw-1 python3-cryptography python3-argon2
python3 main.py
```
