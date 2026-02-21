"""
Binary patcher - Change target from yysls.exe to wwm.exe
Patches both GameHook.dll and Injector.exe without recompiling
"""
import shutil
import os

SOURCE_DIR = r"C:\Users\AD\Desktop\find api\hook"
BACKUP_SUFFIX = ".bak_yysls"

def patch_file(filepath, patches):
    """Apply binary patches to a file"""
    # Backup first
    backup = filepath + BACKUP_SUFFIX
    if not os.path.exists(backup):
        shutil.copy2(filepath, backup)
        print(f"[+] Backup: {backup}")
    
    with open(filepath, 'rb') as f:
        data = f.read()
    
    original_size = len(data)
    
    for old_bytes, new_bytes, desc in patches:
        count = data.count(old_bytes)
        if count == 0:
            print(f"  [!] NOT FOUND: {desc}")
            print(f"      Looking for: {old_bytes}")
            continue
        
        # Pad new_bytes to same length as old_bytes
        if len(new_bytes) < len(old_bytes):
            new_bytes = new_bytes + b'\x00' * (len(old_bytes) - len(new_bytes))
        
        data = data.replace(old_bytes, new_bytes)
        print(f"  [+] Patched {count}x: {desc}")
    
    assert len(data) == original_size, "File size changed! Aborting."
    
    with open(filepath, 'wb') as f:
        f.write(data)
    
    print(f"[+] Saved: {filepath}")

print("=== Binary Patcher: yysls.exe -> wwm.exe ===\n")

# Patch GameHook.dll (ASCII strings)
print("--- Patching GameHook.dll ---")
patch_file(os.path.join(SOURCE_DIR, "GameHook.dll"), [
    # TARGET_MODULE string: "yysls.exe" -> "wwm.exe"
    (b'yysls.exe', b'wwm.exe\x00\x00', "TARGET_MODULE (ASCII)"),
])

# Patch Injector.exe (Wide strings + ASCII strings)
print("\n--- Patching Injector.exe ---")
patch_file(os.path.join(SOURCE_DIR, "Injector.exe"), [
    # Wide string: L"yysls.exe" -> L"wwm.exe"
    # y\0y\0s\0l\0s\0.\0e\0x\0e\0 -> w\0w\0m\0.\0e\0x\0e\0\0\0\0\0
    (
        b'y\x00y\x00s\x00l\x00s\x00.\x00e\x00x\x00e\x00',
        b'w\x00w\x00m\x00.\x00e\x00x\x00e\x00\x00\x00\x00\x00',
        "FindPid target (Wide)"
    ),
    # ASCII printf strings
    (b'yysls.exe', b'wwm.exe\x00\x00', "printf strings (ASCII)"),
])

print("\n=== DONE! ===")
print("GameHook.dll and Injector.exe now target wwm.exe")
print("Original backups saved with .bak_yysls extension")
print("\nTo revert: rename .bak_yysls files back")
