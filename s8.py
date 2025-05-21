import socket
import threading
import ssl
import bcrypt
import sqlite3
from datetime import datetime
from sqlcipher3 import dbapi2 as sqlite
import os


def get_db_connection():
    conn = sqlite.connect('connections_encrypted.db')
    encryption_key = os.environ.get("DB_ENCRYPTION_KEY")
    if not encryption_key:
        raise RuntimeError("Encryption key not set in environment variable DB_ENCRYPTION_KEY")
    conn.execute(f"PRAGMA key = '{encryption_key}';")
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS connections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        ip_address TEXT NOT NULL,
        port INTEGER NOT NULL,
        connection_time TEXT NOT NULL,
        is_online BOOLEAN NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER,
        content TEXT,
        timestamp DATETIME,
        FOREIGN KEY (sender_id) REFERENCES users(id)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS message_recipients (
        message_id INTEGER,
        user_id INTEGER,
        FOREIGN KEY (message_id) REFERENCES messages(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    conn.commit()
    conn.close()

init_db()

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("localhost", 9000))
server_socket.listen(5)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

list_of_clients = []
client_usernames = {}

def clientthread(connstream, addr):
    try:
        connstream.send("AUTH_REQUEST".encode('utf-8'))
        creds = connstream.recv(2048).decode('utf-8')
        username, password = creds.split("||")

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        user_record = cursor.fetchone()

        if not user_record:
            hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            connstream.send("USER_ADDED".encode('utf-8'))
            cursor.execute("""
                INSERT INTO connections (username, ip_address, port, connection_time, is_online)
                VALUES (?, ?, ?, ?, ?)
            """, (username, addr[0], addr[1], datetime.now().strftime('%Y-%m-%d %H:%M:%S'), True))
            conn.commit()
        else:
            if not bcrypt.checkpw(password.encode(), user_record[0].encode()):
                connstream.send("AUTH_FAILED".encode('utf-8'))
                conn.close()
                connstream.close()
                return
            connstream.send("AUTH_SUCCESS".encode('utf-8'))

        cursor.execute("UPDATE connections SET ip_address = ?, port = ?, connection_time = ?, is_online = ? WHERE username = ?",
                       (addr[0], addr[1], datetime.now().strftime('%Y-%m-%d %H:%M:%S'), True, username))
        conn.commit()

        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        sender_id = cursor.fetchone()[0]

        client_usernames[connstream] = username
        list_of_clients.append(connstream)

        connstream.send(f"Welcome to this chatroom, {username}!".encode('utf-8'))

        cursor.execute("""
        SELECT type, content, timestamp, sender_name, recipients FROM (
            SELECT 
                'sent' AS type, 
                m.content, 
                m.timestamp, 
                u.username AS sender_name,
                (SELECT GROUP_CONCAT(u2.username)
                FROM message_recipients mr2
                JOIN users u2 ON mr2.user_id = u2.id
                WHERE mr2.message_id = m.id) AS recipients
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE u.username = ?

            UNION ALL

            SELECT 
                'received' AS type, 
                m.content, 
                m.timestamp, 
                sender.username AS sender_name,
                NULL AS recipients
            FROM messages m
            JOIN message_recipients mr ON m.id = mr.message_id
            JOIN users receiver ON mr.user_id = receiver.id
            JOIN users sender ON m.sender_id = sender.id
            WHERE receiver.username = ?
        )
        ORDER BY timestamp;
    """, (username, username))

        results = cursor.fetchall()
        connstream.send(f"CHAT_HISTORY|{results}".encode('utf-8'))


        while True:
            header = connstream.recv(4096).decode('utf-8')
            if not header:
                break
            message = header
            if header.startswith("/pm "):
                try:
                    _, target_username, private_msg = header.split(" ", 2)
                except ValueError:
                    connstream.send(b"Invalid private message format. Use: /pm username message")
                    return

                cursor.execute("SELECT id FROM users WHERE username = ?", (target_username,))
                result = cursor.fetchone()
                if result:
                    target_user_id = result[0]
                    print(sender_id,target_user_id, target_username, private_msg, _)
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                    cursor.execute("INSERT INTO messages (sender_id, content, timestamp) VALUES (?, ?, ?)", (sender_id, private_msg, timestamp))
                    message_id = cursor.lastrowid

                    cursor.execute("INSERT INTO message_recipients (message_id, user_id) VALUES (?, ?)", (message_id, target_user_id))
                    conn.commit()
                    for client in list_of_clients:
                        if client_usernames.get(client) == target_username:
                            client.send(f"[PM from {username}]: {private_msg}".encode('utf-8'))
                            break

                    connstream.send(f"[PM to {target_username}]: {private_msg}".encode('utf-8'))
                else:
                    connstream.send(b"User not found.")

            elif header.startswith("QUERY|"):
                query_id = header.split("|")[1].strip()
                predefined_queries = {
                    "query1": "SELECT username FROM connections WHERE is_online = 1;",
                    "query2": "SELECT COUNT(*) FROM connections;",
                    "query3": "SELECT * FROM messages m JOIN users u ON m.sender_id = u.id WHERE u.username = ?;",
                    "query4": "SELECT * FROM messages m JOIN message_recipients mr ON m.id = mr.message_id JOIN users u ON mr.user_id = u.id WHERE u.username = ?;",
                    "query5": "SELECT COUNT(*) FROM messages;",
                    "query6": """
                        SELECT u1.username AS sender, u2.username AS receiver, COUNT(*) AS message_count
                        FROM messages m
                        JOIN users u1 ON m.sender_id = u1.id
                        JOIN message_recipients mr ON m.id = mr.message_id
                        JOIN users u2 ON mr.user_id = u2.id
                        GROUP BY sender, receiver;
                    """,
                    "query7": """
                        SELECT 'sent' AS type, m.content, m.timestamp
                        FROM messages m
                        JOIN users u ON m.sender_id = u.id
                        WHERE u.username = ?
                        UNION
                        SELECT 'received' AS type, m.content, m.timestamp
                        FROM messages m
                        JOIN message_recipients mr ON m.id = mr.message_id
                        JOIN users u ON mr.user_id = u.id
                        WHERE u.username = ?
                        ORDER BY timestamp;
                    """
                }
                sql = predefined_queries[query_id]
                if query_id in ["query3", "query4"]:
                    cursor.execute(sql, (username,))
                elif query_id == "query7":
                    cursor.execute(sql, (username, username))
                else:
                    cursor.execute(sql)

                results = cursor.fetchall()
                columns = [desc[0] for desc in cursor.description]
                output = "\t".join(columns) + "\n"
                for row in results:
                    output += "\t".join(str(col) for col in row) + "\n"

                connstream.send(f"QUERY_RESULT|{output}".encode('utf-8'))

            else:
                if header.lower() == "exit":
                    connstream.send("You have exited the chat.".encode('utf-8'))
                    break

                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                cursor.execute("INSERT INTO messages (sender_id, content, timestamp) VALUES (?, ?, ?)", (sender_id, header, timestamp))
                message_id = cursor.lastrowid

                for client in list_of_clients:
                    if client != connstream:
                        target_username = client_usernames[client]
                        cursor.execute("SELECT id FROM users WHERE username = ?", (target_username,))
                        target_user_id = cursor.fetchone()[0]
                        cursor.execute("INSERT INTO message_recipients (message_id, user_id) VALUES (?, ?)", (message_id, target_user_id))
                        client.send(f"<{username}>: {header}".encode('utf-8'))

                conn.commit()

    except Exception as e:
        print("Error:", e)
    finally:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE connections SET is_online = ? WHERE username = ?", (False, username))
        conn.commit()
        conn.close()
        remove(connstream)
        connstream.close()

def remove(connection):
    if connection in list_of_clients:
        list_of_clients.remove(connection)

def get_client_by_username(username):
    for conn, user in client_usernames.items():
        if user == username:
            return conn
    return None

while True:
    client_sock, addr = server_socket.accept()
    connstream = context.wrap_socket(client_sock, server_side=True)
    print(f"{addr[0]} connected with SSL")
    thread = threading.Thread(target=clientthread, args=(connstream, addr))
    thread.start()
