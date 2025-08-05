import socket, threading, base64, json, time
from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import HexEncoder
import customtkinter as ctk
from tkinter import messagebox

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

PORT = 5050

# Encryption setup
my_private = PrivateKey.generate()
my_public = my_private.public_key
peers = {}  # username -> PublicKey

def encrypt_message(to_user, msg):
    if to_user not in peers:
        return None
    box = Box(my_private, peers[to_user])
    encrypted = box.encrypt(msg.encode())
    return base64.b64encode(encrypted).decode()

def decrypt_message(from_user, encrypted):
    box = Box(my_private, peers[from_user])
    decoded = base64.b64decode(encrypted.encode())
    return box.decrypt(decoded).decode()

def ip_to_room_code(ip: str):
    print(ip)
    ip = ip.removeprefix("192.168")
    print(ip)
    return base64.urlsafe_b64encode(ip.encode()).decode().rstrip("=")

def room_code_to_ip(code):
    padded = code + "=" * (-len(code) % 4)
    ip = base64.urlsafe_b64decode(padded.encode()).decode()
    print(ip)
    ip = "192.168" + ip if ip.startswith(".") else ip
    print(ip)
    return ip

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connect to a non-routable IP; doesn't matter if unreachable
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except:
        return "127.0.0.1"
    finally:
        s.close()

# GUI
class ChatApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("@Chat | Encrypted Group Chat")
        self.geometry("500x300")
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.username = ""
        self.conn = None

        self.create_ui()
    
    def copy_to_clipboard(self, text):
        self.clipboard_append(text)
        messagebox.showinfo("Success", f"Text copied to cliboard!\n{text}")

    def create_ui(self):
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(self.main_frame, text="Welcome to @Chat", font=("Arial", 24)).pack(pady=20)
        ctk.CTkButton(self.main_frame, text="Create Chat Room", command=self.create_room_ui).pack(pady=10)
        ctk.CTkButton(self.main_frame, text="Join Chat Room", command=self.join_room_ui).pack(pady=10)

    def create_room_ui(self):
        global room_code
        self.main_frame.destroy()
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(fill="both", expand=True)

        local_ip = get_local_ip()
        room_code = ip_to_room_code(local_ip)

        ctk.CTkLabel(self.main_frame, text="Your Username").pack(pady=10)
        self.name_entry = ctk.CTkEntry(self.main_frame)
        self.name_entry.pack(pady=5)
        ctk.CTkButton(self.main_frame, text="Start Room", command=lambda: self.start_server(local_ip, room_code)).pack(pady=20)
        ctk.CTkLabel(self.main_frame, text=f"Share this room code:").pack(pady=5)
        ctk.CTkLabel(self.main_frame, text=room_code, font=("Arial", 24)).pack(pady=5)
        ctk.CTkButton(self.main_frame, text="Copy to clipboard", command=self.copy_to_clipboard(room_code)).pack(pady=5)

    def join_room_ui(self):
        global room_code
        self.main_frame.destroy()
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(fill="both", expand=True)

        ctk.CTkLabel(self.main_frame, text="Your Username").pack(pady=5)
        self.name_entry = ctk.CTkEntry(self.main_frame)
        self.name_entry.pack(pady=5)

        ctk.CTkLabel(self.main_frame, text="Enter Room Code").pack(pady=5)
        self.code_entry = ctk.CTkEntry(self.main_frame)
        self.code_entry.pack(pady=5)

        room_code = self.code_entry.get().strip()
        
        ctk.CTkButton(self.main_frame, text="Join Room", command=self.connect_to_host).pack(pady=10)

    def setup_chat_ui(self):
        global room_code
        self.geometry("500x600")
        
        self.main_frame.destroy()
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(fill="both", expand=True)
        
        ctk.CTkLabel(self.main_frame, text=room_code, font=("Arial", 24)).pack(pady=10)

        self.chat_display = ctk.CTkTextbox(self.main_frame, height=450)
        self.chat_display.pack(pady=10, padx=10, fill="both", expand=True)
        self.chat_display.configure(state="disabled")

        self.msg_entry = ctk.CTkEntry(self.main_frame)
        self.msg_entry.pack(side="left", fill="x", expand=True, padx=10, pady=10)

        send_btn = ctk.CTkButton(self.main_frame, text="Send", command=self.send_msg)
        send_btn.pack(side="right", padx=10)

    def start_server(self, host_ip, room_code):
        self.username = self.name_entry.get().strip()
        if not self.username:
            messagebox.showerror("Error", "Enter a username")
            return

        self.setup_chat_ui()
        time.sleep(2)
        self.chat_display.insert("end", f"[SYSTEM] Hosting chat on {host_ip}:{PORT}\n[ROOM CODE]: {room_code}\n")

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((host_ip, PORT))
        server.listen()

        clients = {}

        def broadcast(sender, msg):
            for uname, conn in clients.items():
                if uname != sender:
                    try:
                        conn.sendall(json.dumps({"from": sender, "text": msg[sender][uname]}).encode())
                    except:
                        continue

        def handle_client(conn):
            try:
                data = json.loads(conn.recv(4096).decode())
                uname = data["username"]
                peers[uname] = PublicKey(data["public_key"].encode(), encoder=HexEncoder)
                clients[uname] = conn
                self.chat_display.configure(state="normal")
                self.chat_display.insert("end", f"[SYSTEM] {uname} joined.\n")
                self.chat_display.configure(state="disabled")

                # Send public keys to each other
                for other_uname, other_conn in clients.items():
                    if other_uname != uname:
                        other_conn.sendall(json.dumps({"sys": "key_add", "username": uname,
                                                       "public_key": data["public_key"]}).encode())
                        conn.sendall(json.dumps({"sys": "key_add", "username": other_uname,
                                                 "public_key": peers[other_uname].encode(encoder=HexEncoder).decode()}).encode())

                while True:
                    msg_data = json.loads(conn.recv(8192).decode())
                    decrypted = decrypt_message(uname, msg_data["text"])
                    self.chat_display.configure(state="normal")
                    self.chat_display.insert("end", f"{uname}: {decrypted}\n")
                    self.chat_display.configure(state="disabled")

                    rebroadcast = {}
                    for peer in peers:
                        if peer != uname:
                            rebroadcast[uname] = rebroadcast.get(uname, {})
                            rebroadcast[uname][peer] = encrypt_message(peer, decrypted)
                    broadcast(uname, rebroadcast)
            except:
                self.chat_display.insert("end", f"[SYSTEM] {uname} disconnected.\n")

        def accept_clients():
            while True:
                conn, _ = server.accept()
                threading.Thread(target=handle_client, args=(conn,), daemon=True).start()

        threading.Thread(target=accept_clients, daemon=True).start()

    def connect_to_host(self):
        self.username = self.name_entry.get().strip()
        code = self.code_entry.get().strip()
        if not self.username or not code:
            messagebox.showerror("Error", "Enter username and code")
            return

        try:
            host_ip = room_code_to_ip(code)
        except:
            messagebox.showerror("Error", "Invalid room code")
            return

        self.setup_chat_ui()
        self.chat_display.insert("end", f"[SYSTEM] Connecting to {host_ip}:{PORT}...\n")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((host_ip, PORT))
        except Exception as e:
            messagebox.showerror("Error", f"Could not connect: {e}")
            return

        self.conn = s
        s.sendall(json.dumps({"username": self.username,
                              "public_key": my_public.encode(encoder=HexEncoder).decode()}).encode())

        def receive_loop():
            while True:
                try:
                    msg = json.loads(s.recv(8192).decode())
                    if "sys" in msg:
                        uname = msg["username"]
                        pub = PublicKey(msg["public_key"].encode(), encoder=HexEncoder)
                        peers[uname] = pub
                        self.chat_display.configure(state="normal")
                        self.chat_display.insert("end", f"[SYSTEM] {uname} joined.\n")
                        self.chat_display.configure(state="disabled")
                    else:
                        sender = msg["from"]
                        decrypted = decrypt_message(sender, msg["text"])
                        self.chat_display.configure(state="normal")
                        self.chat_display.insert("end", f"{sender}: {decrypted}\n")
                        self.chat_display.configure(state="disabled")
                except:
                    break

        threading.Thread(target=receive_loop, daemon=True).start()

    def send_msg(self):
        msg = self.msg_entry.get().strip()
        self.msg_entry.delete(0, "end")
        if not msg: return

        self.chat_display.configure(state="normal")
        self.chat_display.insert("end", f"You: {msg}\n")
        self.chat_display.configure(state="disabled")

        if self.conn:
            for peer in peers:
                if peer != self.username:
                    enc = encrypt_message(peer, msg)
                    if enc:
                        try:
                            self.conn.sendall(json.dumps({"text": enc}).encode())
                            break
                        except:
                            pass

    def on_close(self):
        self.destroy()

if __name__ == "__main__":
    app = ChatApp()
    app.mainloop()
