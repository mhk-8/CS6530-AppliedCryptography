import sqlite3
import os
import json
import uuid
import functools
from flask import Flask, request, jsonify, g, Response, stream_with_context
from security import (
    load_keys,
    encrypt_data, decrypt_data,
    encrypt_file, decrypt_file_stream,
    hash_data, generate_hmac, verify_hmac
)

# --- App Setup ---

app = Flask(__name__)
app.config['DEBUG'] = True
DB_FILE = "secure-data.db"
UPLOAD_FOLDER = "uploads"

# Create uploads folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Load master keys from our "simulated KMS" (secrets.ini)
# This is done once on startup.
try:
    MEK, AIK = load_keys()
except Exception as e:
    # If keys can't be loaded, the app cannot run securely.
    app.logger.critical(f"CRITICAL STARTUP FAILURE: {e}")
    print(f"CRITICAL STARTUP FAILURE: {e}")
    exit(1) # Exit the application

# --- Database Connection ---

def get_db():
    """Opens a new database connection if one is not already open."""
    if 'db' not in g:
        if not os.path.exists(DB_FILE):
            # This check is crucial for the user
            print("Database not found! Please run 'python database.py' first.")
            raise FileNotFoundError("Database not found! Please run 'python database.py' first.")
        g.db = sqlite3.connect(DB_FILE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    """Closes the database connection at the end of the request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

# --- Decorators (Authentication & Auditing) ---

def get_user(f):
    """Decorator to get user_id from header and pass it to the view function."""
    @functools.wraps(f) # Fix for decorator overwriting
    def decorated_function(*args, **kwargs):
        user_id_str = request.headers.get('X-User-ID')
        if not user_id_str:
            return jsonify({"error": "X-User-ID header is required"}), 401
        try:
            user_id = int(user_id_str)
            return f(user_id=user_id, *args, **kwargs)
        except ValueError:
            return jsonify({"error": "Invalid X-User-ID"}), 401
    return decorated_function

def admin_required(f):
    """Decorator to ensure the user has the 'Admin' role (role_id=1)."""
    @functools.wraps(f) # Fix for decorator overwriting
    def decorated_function(user_id, *args, **kwargs):
        conn = get_db()
        # We assume Admin role_id is 1, as set in database.py
        role = conn.execute(
            "SELECT role_id FROM user_roles WHERE user_id = ? AND role_id = 1", 
            (user_id,)
        ).fetchone()
        
        if role:
            return f(user_id=user_id, *args, **kwargs)
        
        log_audit(user_id, "ADMIN_ACCESS_DENIED", None, "FAILED")
        return jsonify({"error": "Admin access required"}), 403
    return decorated_function

def log_audit(user_id, action, resource_id, status, reason="N/A"):
    """Helper function to log audit events to the console."""
    # In a real app, this would write to a secure, append-only log file or service.
    try:
        conn = get_db()
        user_row = conn.execute("SELECT username FROM users WHERE user_id = ?", (user_id,)).fetchone()
        user_name = user_row['username'] if user_row else f"User {user_id}"
        
        res_name = "N/A"
        if resource_id:
            res_row = conn.execute("SELECT name FROM resources WHERE resource_id = ?", (resource_id,)).fetchone()
            res_name = res_row['name'] if res_row else f"ID {resource_id}"
        
        print(f"[AUDIT] {user_name} ({user_id}) check '{action}' on resource {res_name} ({resource_id}) > {status} ({reason})")
    except Exception as e:
        # Fallback in case logging fails (e.g., during a failed DB connection)
        print(f"[AUDIT] FAILED TO LOG: {e}")

# --- Core Enforcement Engine ---

def get_parent_folders(conn, resource_id):
    """Recursively get all parent folder IDs for a given resource."""
    parents = []
    current_id = resource_id
    
    # Get the resource's own parent first
    row = conn.execute("SELECT parent_id FROM resources WHERE resource_id = ?", (current_id,)).fetchone()
    if row and row['parent_id'] is not None:
        current_id = row['parent_id']
        parents.append(current_id)
    else:
        return [] # No parents
        
    # We limit to 10 levels deep to prevent infinite loops on bad data
    for _ in range(10): 
        row = conn.execute("SELECT parent_id FROM resources WHERE resource_id = ?", (current_id,)).fetchone()
        if row and row['parent_id'] is not None:
            parents.append(row['parent_id'])
            current_id = row['parent_id']
            if current_id == 1: # Reached root
                break
        else:
            break # No parent
    return parents

def check_permission(user_id, resource_id, requested_action):
    """
    The heart of the access control system.
    Checks DAC (owner, ACL) and RBAC (roles) to see if a user can perform an action.
    Returns (True, "Reason") or (False, "Reason").
    """
    conn = get_db()
    
    # 1. Check Ownership (Implicit DAC)
    resource = conn.execute("SELECT owner_user_id, resource_type FROM resources WHERE resource_id = ?", (resource_id,)).fetchone()
    if not resource:
        return False, "Resource not found"
    
    if resource['owner_user_id'] == user_id:
        return True, "DAC_OWNER"
    
    # 2. Check ACLs (Explicit DAC)
    acl_row = conn.execute(
        "SELECT encrypted_permissions, hmac FROM acls WHERE resource_id = ? AND target_user_id = ?",
        (resource_id, user_id)
    ).fetchone()
    
    if acl_row:
        try:
            # Verify HMAC to ensure data integrity
            # We must use the exact same format as when we created it
            message = f"{acl_row['encrypted_permissions']}:{resource_id}:{user_id}"
            
            if not verify_hmac(AIK, acl_row['hmac'], message):
                log_audit(user_id, requested_action, resource_id, "FAILED", "DAC_HMAC_INVALID")
                return False, "Security Error: ACL integrity check failed"
            
            # Decrypt permissions
            decrypted_json = decrypt_data(MEK, acl_row['encrypted_permissions'])
            permissions = json.loads(decrypted_json)
            
            if requested_action in permissions:
                return True, "DAC_ACL"
            
        except Exception as e:
            log_audit(user_id, requested_action, resource_id, "FAILED", f"DAC_DECRYPT_FAIL: {e}")
            return False, "Security Error: Could not process ACL"
            
    # 3. Check Roles (RBAC) - This is the most complex check
    # We must check the resource itself (if it's a folder) AND all parent folders.
    folder_ids_to_check = []
    if resource['resource_type'] == 'folder':
        folder_ids_to_check.append(resource_id)
        
    folder_ids_to_check.extend(get_parent_folders(conn, resource_id))
    
    if not folder_ids_to_check:
        # This is a file with no ACL, and no parent folders... should be denied
        return False, "FAILED (No permissions found)"
        
    # This query joins user->roles, roles->permissions, and permissions->actions
    # for all folders in the resource's hierarchy.
    query = """
    SELECT p.action_name, rp.resource_id
    FROM user_roles ur
    JOIN role_permissions rp ON ur.role_id = rp.role_id
    JOIN permissions p ON rp.permission_id = p.permission_id
    WHERE ur.user_id = ? AND p.action_name = ? AND rp.resource_id IN ({placeholders})
    """.format(placeholders=','.join('?' * len(folder_ids_to_check)))
    
    params = [user_id, requested_action] + folder_ids_to_check
    
    rbac_perm = conn.execute(query, params).fetchone()
    
    if rbac_perm:
        if rbac_perm['resource_id'] == resource_id:
            return True, "RBAC_DIRECT"
        else:
            return True, f"RBAC_INHERITED (from folder {rbac_perm['resource_id']})"

    # 4. Default Deny
    return False, "FAILED"

# --- Admin API Endpoints (RBAC Management) ---

@app.route('/api/admin/roles/<int:role_id>/assign-permission', methods=['POST'], endpoint='admin_assign_perm')
@get_user
@admin_required
def admin_assign_perm(user_id, role_id):
    """Admin: Assigns a permission to a role for a specific folder."""
    data = request.json
    permission_id = data.get('permission_id')
    resource_id = data.get('resource_id')
    
    if not all([permission_id, resource_id]):
        return jsonify({"error": "Missing 'permission_id' or 'resource_id'"}), 400
        
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO role_permissions (role_id, permission_id, resource_id) VALUES (?, ?, ?)",
            (role_id, permission_id, resource_id)
        )
        conn.commit()
        log_audit(user_id, f"ADMIN_GRANT role {role_id} perm {permission_id} on folder {resource_id}", resource_id, "SUCCESS")
        return jsonify({"status": "success", "role_id": role_id, "permission_id": permission_id, "resource_id": resource_id}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Permission already exists or invalid IDs"}), 409
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- File Management API Endpoints (DAC & RBAC in action) ---

@app.route('/api/files/upload', methods=['POST'], endpoint='upload_file')
@get_user
# Note: @log_audit removed
def upload_file(user_id): # Note: extra arguments removed
    """
    Uploads a new file.
    The user must have 'write' permission on the parent folder.
    """
    # 1. Get file and metadata from the request
    if 'file' not in request.files:
        return jsonify({"error": "No 'file' part in request"}), 400
    
    file = request.files['file']
    filename = file.filename
    parent_id = request.form.get('parent_id')
    
    if not parent_id:
        return jsonify({"error": "Missing 'parent_id' (folder ID) in form data"}), 400
        
    try:
        parent_id = int(parent_id)
    except ValueError:
        return jsonify({"error": "Invalid 'parent_id'"}), 400

    # 2. Check Permission (Enforcement Engine)
    # We check if the user can 'write' to the parent folder
    allowed, reason = check_permission(user_id, parent_id, 'write')
    # Manual log call (this is correct)
    log_audit(user_id, 'write', parent_id, "SUCCESS" if allowed else "FAILED", reason)
    
    if not allowed:
        return jsonify({"error": f"Permission denied. Reason: {reason}"}), 403

    # 3. Process and encrypt the file
    try:
        file_bytes = file.read()
        file_hash = hash_data(file_bytes)
        
        # Encrypts the file and returns the encrypted FEK (as hex)
        encrypted_content, fek = encrypt_file(MEK, file_bytes)
        
        # Save encrypted file to disk
        file_uuid = str(uuid.uuid4())
        storage_path = os.path.join(UPLOAD_FOLDER, file_uuid)
        with open(storage_path, 'wb') as f:
            f.write(encrypted_content)
        
        # 4. Save metadata to database
        conn = get_db()
        cursor = conn.cursor()
        
        # Create the 'resource' entry
        cursor.execute(
            "INSERT INTO resources (name, resource_type, owner_user_id, parent_id) VALUES (?, 'file', ?, ?)",
            (filename, user_id, parent_id)
        )
        resource_id = cursor.lastrowid
        
        # Create the 'file_metadata' entry
        # This is the line that was fixed (no .hex())
        cursor.execute(
            "INSERT INTO file_metadata (file_id, storage_path, encrypted_file_key, file_hash) VALUES (?, ?, ?, ?)",
            (resource_id, storage_path, fek, file_hash)
        )
        conn.commit()
        
        return jsonify({"status": "File uploaded", "resource_id": resource_id, "filename": filename}), 201
        
    except Exception as e:
        app.logger.error(f"Upload failed: {e}")
        print(f"[ERROR] Upload failed: {e}")
        return jsonify({"error": "File upload failed"}), 500

@app.route('/api/files/<int:resource_id>/download', methods=['GET'], endpoint='download_file')
@get_user
# Note: @log_audit removed
def download_file(user_id, resource_id): # Note: extra arguments removed
    """
    Downloads a file.
    The user must have 'read' permission (from DAC or RBAC).
    """
    # 1. Check Permission (Enforcement Engine)
    allowed, reason = check_permission(user_id, resource_id, 'read')
    # Manual log call (this is correct)
    log_audit(user_id, 'read', resource_id, "SUCCESS" if allowed else "FAILED", reason)
    
    if not allowed:
        return jsonify({"error": f"Permission denied. Reason: {reason}"}), 403

    # 2. Get file metadata
    conn = get_db()
    meta = conn.execute(
        "SELECT r.name, fm.storage_path, fm.encrypted_file_key FROM file_metadata fm "
        "JOIN resources r ON fm.file_id = r.resource_id WHERE fm.file_id = ?",
        (resource_id,)
    ).fetchone()
    
    if not meta:
        return jsonify({"error": "File not found"}), 404
        
    # 3. Stream the decrypted file
    # We use a generator and stream_with_context to handle large files
    # without loading them all into memory.
    try:
        decryption_generator = decrypt_file_stream(MEK, meta['encrypted_file_key'], meta['storage_path'])
        
        return Response(stream_with_context(decryption_generator), headers={
            'Content-Disposition': f'attachment; filename="{meta["name"]}"'
        })
    except Exception as e:
        app.logger.error(f"Download failed: {e}")
        print(f"[ERROR] Download failed: {e}")
        return jsonify({"error": f"File decryption failed: {e}"}), 500

@app.route('/api/files/<int:resource_id>/share', methods=['POST'], endpoint='share_file')
@get_user
# Note: @log_audit removed
def share_file(user_id, resource_id): # Note: extra arguments removed
    """
    Shares a file with another user (Explicit DAC).
    The user must be the 'owner' of the file.
    """
    # 1. Check Permission (Must be owner to share)
    # We don't use check_permission here, as 'share' is a special action
    # only the owner can do.
    conn = get_db()
    resource = conn.execute("SELECT owner_user_id FROM resources WHERE resource_id = ?", (resource_id,)).fetchone()
    
    if not resource:
        return jsonify({"error": "Resource not found"}), 404
        
    if resource['owner_user_id'] != user_id:
        log_audit(user_id, 'share', resource_id, "FAILED", "Not owner")
        return jsonify({"error": "Permission denied. Only the owner can share."}), 403

    # 2. Get request data
    data = request.json
    target_user_id = data.get('target_user_id')
    permissions = data.get('permissions') # e.g., ['read'] or ['read', 'write']
    
    if not all([target_user_id, isinstance(permissions, list)]):
        return jsonify({"error": "Missing 'target_user_id' or 'permissions' (must be a list)"}), 400

    # 3. Create the secure ACL
    try:
        permissions_json = json.dumps(permissions)
        
        # Encrypt the permissions list
        encrypted_perms = encrypt_data(MEK, permissions_json)
        
        # Create HMAC for integrity
        message = f"{encrypted_perms}:{resource_id}:{target_user_id}"
        hmac_tag = generate_hmac(AIK, message)
        
        # Generate a unique ID for the ACL
        acl_id = str(uuid.uuid4())
        
        # Insert or replace the ACL
        conn.execute(
            "REPLACE INTO acls (acl_id, resource_id, target_user_id, encrypted_permissions, hmac) "
            "VALUES (?, ?, ?, ?, ?)",
            (acl_id, resource_id, target_user_id, encrypted_perms, hmac_tag)
        )
        conn.commit()
        
        log_audit(user_id, f"SHARE with {target_user_id}", resource_id, "SUCCESS")
        return jsonify({"status": "Share successful", "resource_id": resource_id, "target_user_id": target_user_id}), 200
        
    except Exception as e:
        app.logger.error(f"Share failed: {e}")
        print(f"[ERROR] Share failed: {e}")
        return jsonify({"error": f"Could not create secure ACL: {e}"}), 500

@app.route('/api/files/<int:resource_id>/revoke', methods=['POST'], endpoint='revoke_share')
@get_user
# Note: @log_audit removed
def revoke_share(user_id, resource_id): # Note: extra arguments removed
    """
    Revokes access for a user from a file (Explicit DAC).
    The user must be the 'owner'.
    """
    # 1. Check Permission (Must be owner to revoke)
    conn = get_db()
    resource = conn.execute("SELECT owner_user_id FROM resources WHERE resource_id = ?", (resource_id,)).fetchone()
    
    if not resource:
        return jsonify({"error": "Resource not found"}), 404
        
    if resource['owner_user_id'] != user_id:
        log_audit(user_id, 'revoke', resource_id, "FAILED", "Not owner")
        return jsonify({"error": "Permission denied. Only the owner can revoke."}), 403

    # 2. Get request data
    target_user_id = request.json.get('target_user_id')
    if not target_user_id:
        return jsonify({"error": "Missing 'target_user_id'"}), 400
        
    # 3. Delete the ACL
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM acls WHERE resource_id = ? AND target_user_id = ?",
        (resource_id, target_user_id)
    )
    conn.commit()
    
    if cursor.rowcount > 0:
        log_audit(user_id, f"REVOKE from {target_user_id}", resource_id, "SUCCESS")
        return jsonify({"status": "Revoke successful"}), 200
    else:
        log_audit(user_id, f"REVOKE from {target_user_id}", resource_id, "FAILED", "No existing ACL")
        return jsonify({"error": "No share found for that user"}), 404

# --- Main execution ---
if __name__ == '__main__':
    # We must check if the DB exists *before* starting the app
    if not os.path.exists(DB_FILE):
        print(f"CRITICAL: Database file '{DB_FILE}' not found.")
        print("Please run 'python database.py' first to create and populate it.")
        exit(1)
        
    app.run(debug=True, port=5000)

