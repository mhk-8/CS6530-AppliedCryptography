import requests
import os

# --- Client Configuration ---
BASE_URL = "http://127.0.0.1:5000"

# User IDs (match database.py)
ADMIN_ID = 1
ALICE_ID = 2
BOB_ID = 3
CAROL_ID = 4

# Resource IDs (match database.py)
ROOT_FOLDER_ID = 1
ENGINEERING_FOLDER_ID = 2
HR_FOLDER_ID = 3

# Permission IDs (match database.py)
PERM_READ = 1
PERM_WRITE = 2
PERM_DELETE = 3
PERM_SHARE = 4
PERM_AUDIT = 5

# Local files to create for testing
ALICE_FILE = "alice_secret.txt"
BOB_FILE = "bob_plan.txt"

# --- Helper Functions ---

def_headers = {'Content-Type': 'application/json'}

def log_client(message):
    print(f"[CLIENT] {message}")

def log_server(status, data):
    print(f"[SERVER] STATUS: {status}, DATA: {data}")
    
def log_demo(message):
    print(f"\n[DEMO] --- {message} ---")

def log_user(username, message):
    print(f"[{username.upper()}] {message}")

def setup_local_files():
    """Creates dummy files for uploading."""
    log_client("Setting up local test directories...")
    with open(ALICE_FILE, "w") as f:
        f.write(f"This is Alice's (User {ALICE_ID}) secret engineering spec.")
    with open(BOB_FILE, "w") as f:
        f.write(f"This is Bob's (User {BOB_ID}) marketing plan.")

def cleanup_local_files():
    """Removes dummy files."""
    log_client("Cleaning up local test files...")
    if os.path.exists(ALICE_FILE):
        os.remove(ALICE_FILE)
    if os.path.exists(BOB_FILE):
        os.remove(BOB_FILE)
    
    # Clean up downloaded files
    if os.path.exists("downloaded_by_alice.txt"):
        os.remove("downloaded_by_alice.txt")
    if os.path.exists("downloaded_by_carol.txt"):
        os.remove("downloaded_by_carol.txt")

def setup_environment(admin_id):
    """(Admin) Sets up the RBAC permissions for the demo."""
    log_user("Admin", f"(User {admin_id}) is setting up the demo environment...")
    headers = {'X-User-ID': str(admin_id), 'Content-Type': 'application/json'}
    
    # 1. Grant 'Engineer' (Role 2) 'write' (Perm 2) on 'Engineering' (Folder 2)
    url = f"{BASE_URL}/api/admin/roles/2/assign-permission"
    data = {"permission_id": PERM_WRITE, "resource_id": ENGINEERING_FOLDER_ID}
    r = requests.post(url, headers=headers, json=data)
    log_server(r.status_code, r.json())

    # 2. Grant 'HR' (Role 4) 'write' (Perm 2) on 'HR' (Folder 3)
    url = f"{BASE_URL}/api/admin/roles/4/assign-permission"
    data = {"permission_id": PERM_WRITE, "resource_id": HR_FOLDER_ID}
    r = requests.post(url, headers=headers, json=data)
    log_server(r.status_code, r.json())
    
    # 3. Grant 'Engineer' (Role 2) 'read' (Perm 1) on 'Engineering' (Folder 2)
    # This allows them to see the folder, which is implied by 'write' but good to be explicit
    url = f"{BASE_URL}/api/admin/roles/2/assign-permission"
    data = {"permission_id": PERM_READ, "resource_id": ENGINEERING_FOLDER_ID}
    r = requests.post(url, headers=headers, json=data)
    log_server(r.status_code, r.json())

def upload_file(user_id, username, filename, folder_id):
    """Simulates a user uploading a file."""
    log_user(username, f"Uploading '{filename}' to /Engineering (Folder ID {folder_id})...")
    headers = {'X-User-ID': str(user_id)}
    
    with open(filename, 'rb') as f:
        files = {'file': (filename, f)}
        data = {'parent_id': folder_id}
        r = requests.post(f"{BASE_URL}/api/files/upload", headers=headers, files=files, data=data)
    
    try:
        log_server(r.status_code, r.json())
    except requests.exceptions.JSONDecodeError:
        log_server(r.status_code, "(No JSON response)")
        
    if r.status_code == 201:
        log_user(username, f"SUCCESS: File uploaded (ID: {r.json().get('resource_id')})")
        return r.json().get('resource_id')
    else:
        log_user(username, "FAILED to upload file.")
        if r.status_code == 403:
             log_user(username, "Server returned 403. (This is the correct behavior!)")
        return None

def download_file(user_id, username, file_id, save_as):
    """Simulates a user downloading a file."""
    log_user(username, f"Attempting to download file ID {file_id}...")
    headers = {'X-User-ID': str(user_id)}
    
    try:
        r = requests.get(f"{BASE_URL}/api/files/{file_id}/download", headers=headers, stream=True)
        
        if r.status_code == 200:
            with open(save_as, 'wb') as f:
                for chunk in r.iter_content(chunk_size=1024):
                    f.write(chunk)
            log_user(username, f"SUCCESS: File downloaded and saved as '{save_as}'.")
            log_server(r.status_code, f"(File content streamed)")
            return True
        else:
            log_server(r.status_code, r.json())
            log_user(username, "FAILED to download file.")
            return False
            
    except Exception as e:
        log_client(f"Download request failed: {e}")
        return False

def share_file(user_id, username, file_id, target_user_id, permissions):
    """Simulates a user sharing a file (DAC)."""
    log_user(username, f"Sharing file ID {file_id} with User {target_user_id} with permissions: {permissions}...")
    headers = {'X-User-ID': str(user_id), 'Content-Type': 'application/json'}
    data = {"target_user_id": target_user_id, "permissions": permissions}
    
    r = requests.post(f"{BASE_URL}/api/files/{file_id}/share", headers=headers, json=data)
    log_server(r.status_code, r.json())
    
    if r.status_code == 200:
        log_user(username, "SUCCESS: File shared.")
    else:
        log_user(username, "FAILED to share file.")

def revoke_share(user_id, username, file_id, target_user_id):
    """Simulates a user revoking a share (DAC)."""
    log_user(username, f"Revoking access for User {target_user_id} from file ID {file_id}...")
    headers = {'X-User-ID': str(user_id), 'Content-Type': 'application/json'}
    data = {"target_user_id": target_user_id}
    
    r = requests.post(f"{BASE_URL}/api/files/{file_id}/revoke", headers=headers, json=data)
    log_server(r.status_code, r.json())
    
    if r.status_code == 200:
        log_user(username, "SUCCESS: Access revoked.")
    else:
        log_user(username, "FAILED to revoke access.")

# --- Main Demonstration ---

def main_demo():
    print("--- Secure Hybrid DMS Client Demo ---")
    alice_file_id = None
    
    try:
        setup_local_files()
        setup_environment(ADMIN_ID)
        
        # --- 1. RBAC Test ---
        log_demo("Testing RBAC (Uploads)")
        
        # Alice (Engineer) uploads to Engineering folder. This should succeed.
        alice_file_id = upload_file(ALICE_ID, "Alice", ALICE_FILE, ENGINEERING_FOLDER_ID)
        
        # Bob (Marketing) uploads to Engineering folder. This should fail.
        upload_file(BOB_ID, "Bob", BOB_FILE, ENGINEERING_FOLDER_ID)

        if not alice_file_id:
            log_demo("Alice's file failed to upload. Cannot continue demo.")
            return

        # --- 2. DAC (Owner) Test ---
        log_demo("Testing DAC (Owner Download)")
        
        # Alice (Owner) downloads her own file. This should succeed.
        download_file(ALICE_ID, "Alice", alice_file_id, "downloaded_by_alice.txt")
        
        # Bob (No perms) downloads Alice's file. This should fail.
        download_file(BOB_ID, "Bob", alice_file_id, "downloaded_by_bob.txt")

        # --- 3. DAC (ACL Share) Test ---
        log_demo("Testing DAC (ACL Sharing)")
        
        # Alice (Owner) shares her file with Carol (HR) with 'read' perms.
        share_file(ALICE_ID, "Alice", alice_file_id, CAROL_ID, ['read'])
        
        # Carol (now has ACL perms) downloads Alice's file. This should succeed.
        download_file(CAROL_ID, "Carol", alice_file_id, "downloaded_by_carol.txt")

        # --- 4. DAC (ACL Revoke) Test ---
        log_demo("Testing DAC (ACL Revoke)")
        
        # Alice (Owner) revokes Carol's access.
        revoke_share(ALICE_ID, "Alice", alice_file_id, CAROL_ID)
        
        # Carol (perms revoked) tries to download again. This should fail.
        download_file(CAROL_ID, "Carol", alice_file_id, "downloaded_by_carol_2.txt")

    except requests.exceptions.ConnectionError:
        print("\n[CLIENT] CRITICAL ERROR: Could not connect to the server.")
        print("Is 'python app.py' running in another terminal?")
    except Exception as e:
        print(f"\n[CLIENT] An unexpected error occurred: {e}")
    finally:
        cleanup_local_files()
        print("\n--- Demo Finished ---")

if __name__ == "__main__":
    main_demo()

