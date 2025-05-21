import socket
import ssl
import threading
import os
import sys
import cmd
import ast
from sqlcipher3 import dbapi2 as sqlite

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_client = context.wrap_socket(client_socket, server_hostname="localhost")
ssl_client.connect(("localhost", 9000))

auth_prompt = ssl_client.recv(1024).decode('utf-8')
if auth_prompt == "AUTH_REQUEST":
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    ssl_client.send(f"{username}||{password}".encode('utf-8'))

    auth_result = ssl_client.recv(1024).decode('utf-8')
    if auth_result == "AUTH_FAILED":
        print("Authentication failed.")
        ssl_client.close()
        sys.exit()
    elif auth_result == "USER_ADDED":
        print("New user created.")
    elif auth_result == "AUTH_SUCCESS":
        print("Authentication successful.")

def receive_messages():
    while True:
        try:
            header = ssl_client.recv(4096).decode('utf-8')
            if header.startswith("QUERY_RESULT|"):
                result = header.split("|", 1)[1]
                print(f"\n[QUERY RESULT]\n{result}")
            
            elif header.startswith("CHAT_HISTORY|"):
                raw_data = header.split("|", 1)[1]
                results = ast.literal_eval(raw_data)

                history_output = "[CHAT HISTORY]\n"
                GREEN = "\033[92m"
                BLUE = "\033[94m"
                RESET = "\033[0m"
                for row in results:
                    if row[0] == "sent":
                        direction = "You"
                        recipients = row[4] or "None"
                        line = f"{direction} at {row[2]} to [{recipients}]: {row[1]}"
                    else:
                        direction = f"From {row[3]}"
                        line = f"{direction} at {row[2]}: {row[1]}"
                    if row[0] == "sent":
                        history_output += f"{GREEN}{line}{RESET}\n"
                    else:
                        history_output += f"{BLUE}{line}{RESET}\n"


                print(history_output)
            elif header.startswith("FILE|"):
                pass
            else:
                print(header)
        except Exception as e:
            print("Connection closed:", e)
            break


class ChatShell(cmd.Cmd):
    intro = "Welcome to the chat shell. Type help or ? to list commands."
    prompt = "(chat) "

    def default(self, line):
        ssl_client.send(line.encode('utf-8'))

    def do_exit(self, arg):
        """Exit the chat"""
        ssl_client.send("exit".encode('utf-8'))
        ssl_client.close()
        print("Disconnected.")
        return True

    def do_query1(self, arg): self.send_query("query1")
    def do_query2(self, arg): self.send_query("query2")
    def do_query3(self, arg): self.send_query("query3")
    def do_query4(self, arg): self.send_query("query4")
    def do_query5(self, arg): self.send_query("query5")
    def do_query6(self, arg): self.send_query("query6")
    def do_query7(self, arg): self.send_query("query7")

    def send_query(self, query_id):
        ssl_client.send(f"QUERY|{query_id}".encode('utf-8'))

    def do_sendfile(self, arg):
        try:
            target_username, filepath = arg.split(" ", 1)
            if os.path.exists(filepath):
                filename = os.path.basename(filepath)
                filesize = os.path.getsize(filepath)
                with open(filepath, "rb") as f:
                    filedata = f.read()
                header = f"FILE|{target_username}|{filename}|{filesize}"
                ssl_client.send(header.encode('utf-8'))
                ssl_client.sendall(filedata)
                print(f"Sent file {filename}")
            else:
                print("File not found.")
        except Exception as e:
            print("Error:", e)

threading.Thread(target=receive_messages, daemon=True).start()
ChatShell().cmdloop()


# qf+!w?kPh-zt}sH@h4R!LeCXN}!1c8?6Jx?tC1n_3v!]Zzi33TBA*,-2u,=fZcew5eB_J>MeTmiX@ZynRR1Y*)w>@tzcV68XPhKv