import sqlite3
import os

DB_FILE = "secure-data.db"

def create_database():
    """
    Creates all necessary tables for the secure DMS.
    This function is idempotent (safe to run multiple times).
    """
    # Delete old database file if it exists, to start clean
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
        print("Removed old database.")
        
    print("Creating new database...")
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # --- Core Tables ---
    cursor.execute('''
    CREATE TABLE users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL
    )
    ''')

    cursor.execute('''
    CREATE TABLE resources (
        resource_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        resource_type TEXT NOT NULL CHECK(resource_type IN ('folder', 'file')),
        owner_user_id INTEGER NOT NULL,
        parent_id INTEGER, -- NULL for the root folder
        FOREIGN KEY (owner_user_id) REFERENCES users(user_id),
        FOREIGN KEY (parent_id) REFERENCES resources(resource_id)
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE file_metadata (
        file_id INTEGER PRIMARY KEY, -- 1:1 with resources.resource_id
        storage_path TEXT NOT NULL,
        encrypted_file_key TEXT NOT NULL, -- Stored as hex
        file_hash TEXT NOT NULL,
        FOREIGN KEY (file_id) REFERENCES resources(resource_id)
    )
    ''')

    # --- RBAC Tables ---
    cursor.execute('''
    CREATE TABLE roles (
        role_id INTEGER PRIMARY KEY AUTOINCREMENT,
        role_name TEXT UNIQUE NOT NULL
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE permissions (
        permission_id INTEGER PRIMARY KEY AUTOINCREMENT,
        action_name TEXT UNIQUE NOT NULL -- 'read', 'write', 'delete', 'share'
    )
    ''')

    cursor.execute('''
    CREATE TABLE user_roles (
        user_id INTEGER NOT NULL,
        role_id INTEGER NOT NULL,
        PRIMARY KEY (user_id, role_id),
        FOREIGN KEY (user_id) REFERENCES users(user_id),
        FOREIGN KEY (role_id) REFERENCES roles(role_id)
    )
    ''')

    cursor.execute('''
    CREATE TABLE role_permissions (
        role_id INTEGER NOT NULL,
        permission_id INTEGER NOT NULL,
        resource_id INTEGER NOT NULL, -- This is the folder ID
        PRIMARY KEY (role_id, permission_id, resource_id),
        FOREIGN KEY (role_id) REFERENCES roles(role_id),
        FOREIGN KEY (permission_id) REFERENCES permissions(permission_id),
        FOREIGN KEY (resource_id) REFERENCES resources(resource_id)
    )
    ''')

    # --- DAC Table ---
    cursor.execute('''
    CREATE TABLE acls (
        acl_id TEXT PRIMARY KEY,
        resource_id INTEGER NOT NULL,
        target_user_id INTEGER NOT NULL,
        encrypted_permissions TEXT NOT NULL,
        hmac TEXT NOT NULL,
        UNIQUE (resource_id, target_user_id),
        FOREIGN KEY (resource_id) REFERENCES resources(resource_id),
        FOREIGN KEY (target_user_id) REFERENCES users(user_id)
    )
    ''')
    
    print("All tables created successfully.")
    return conn

def populate_database(conn):
    """
    Populates the database with initial data (users, roles, permissions).
    """
    print("Populating initial data...")
    cursor = conn.cursor()

    # 1. Create permissions
    permissions = ['read', 'write', 'delete', 'share', 'audit']
    for perm in permissions:
        cursor.execute("INSERT INTO permissions (action_name) VALUES (?)", (perm,))
    
    # 2. Create users
    users = ['admin', 'alice', 'bob', 'carol']
    for user in users:
        cursor.execute("INSERT INTO users (username) VALUES (?)", (user,))

    # 3. Create roles
    roles = ['Admin', 'Engineer', 'Marketing', 'HR']
    for role in roles:
        cursor.execute("INSERT INTO roles (role_name) VALUES (?)", (role,))

    # 4. Assign users to roles
    # User 1 (admin) -> Admin (Role 1)
    cursor.execute("INSERT INTO user_roles (user_id, role_id) VALUES (1, 1)")
    # User 2 (alice) -> Engineer (Role 2)
    cursor.execute("INSERT INTO user_roles (user_id, role_id) VALUES (2, 2)")
    # User 3 (bob) -> Marketing (Role 3)
    cursor.execute("INSERT INTO user_roles (user_id, role_id) VALUES (3, 3)")
    # User 4 (carol) -> HR (Role 4)
    cursor.execute("INSERT INTO user_roles (user_id, role_id) VALUES (4, 4)")
    
    # 5. Create root folders
    # Admin (User 1) owns all root folders
    admin_id = 1
    # Root folder
    cursor.execute(
        "INSERT INTO resources (resource_id, name, resource_type, owner_user_id, parent_id) VALUES (1, '/', 'folder', ?, NULL)",
        (admin_id,)
    )
    # Engineering folder
    cursor.execute(
        "INSERT INTO resources (resource_id, name, resource_type, owner_user_id, parent_id) VALUES (2, 'Engineering', 'folder', ?, 1)",
        (admin_id,)
    )
    # HR folder
    cursor.execute(
        "INSERT INTO resources (resource_id, name, resource_type, owner_user_id, parent_id) VALUES (3, 'HR', 'folder', ?, 1)",
        (admin_id,)
    )

    conn.commit()
    print("Initial data populated.")

if __name__ == "__main__":
    try:
        conn = create_database()
        populate_database(conn)
        conn.close()
        print(f"Database setup complete. File '{DB_FILE}' is ready.")
    except Exception as e:
        print(f"An error occurred: {e}")
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE) # Clean up broken db file

