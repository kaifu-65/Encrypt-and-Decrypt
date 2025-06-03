import hashlib
import sqlite3
from database import connect_to_database

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login(username, password):
    conn = connect_to_database()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Users WHERE username = ? AND password = ?", (username, hash_password(password)))
    user = cursor.fetchone()
    conn.close()
    return user

def signup(username, password):
    conn = connect_to_database()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO Users (username, password) VALUES (?, ?)", (username, hash_password(password)))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return False
    conn.close()
    return True

def save_history(username, action, mode, message, key, output):
    conn = connect_to_database()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO History (username, action, mode, message, key, output) VALUES (?, ?, ?, ?, ?, ?)", 
                   (username, action, mode, message, key, output))
    conn.commit()
    conn.close()

def get_history(username):
    conn = connect_to_database()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM History WHERE username = ? ORDER BY timestamp DESC", (username,))
    history = cursor.fetchall()
    conn.close()
    return history
