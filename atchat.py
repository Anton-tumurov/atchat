import os, socket, threading, json, time
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# === CONFIG ===
BROADCAST_PORT = 50002
MSG_PORT = 50003
MSG_DIR = "messages"
KEY_DIR = "keys"
PEER_DIR = "peers"
os.makedirs(MSG_DIR, exist_ok=True)
os.makedirs(KEY_DIR, exist_ok=True)
os.makedirs(PEER_DIR, exist_ok=True)

# === PLACEHOLDER LOGIN ===
def login():
    Username = input("Enter Username: ")  # TODO: Replace this with your auth system
    return Username
username = login()

# === LOAD / GENERATE RSA KEYS ===
from_path = lambda name: os.path.join(KEY_DIR, name)
priv_path = from_path("private.pem")
pub_path  = from_path("public.pem")

if not os.path.exists(priv_path):
    key = RSA.generate(4096)
    with open(priv_path, 'wb') as f: f.write(key.export_key())
    with open(pub_path, 'wb') as f: f.write(key.publickey().export_key())

with open(priv_path, 'rb') as f:
    priv_key = RSA.import_key(f.read())
    priv_cipher = PKCS1_OAEP.new(priv_key)

with open(pub_path, 'rb') as f:
    my_pub_key = f.read()

# === PEER DISCOVERY ===
peers = {}  # name -> (ip, pubkey)

def save_peer(name, pubkey):
    with open(os.path.join(PEER_DIR, f"{name}.pem"), 'wb') as f:
        f.write(pubkey)

def load_peer(name):
    try:
        with open(os.path.join(PEER_DIR, f"{name}.pem"), 'rb') as f:
            return RSA.import_key(f.read())
    except:
        return None

def broadcast_presence():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    packet = json.dumps({
        "name": username,
        "pubkey": my_pub_key.decode()
    }).encode()
    while True:
        sock.sendto(packet, ("255.255.255.255", BROADCAST_PORT))
        time.sleep(5)

def listen_for_peers():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', BROADCAST_PORT))
    while True:
        data, addr = sock.recvfrom(8192)
        try:
            obj = json.loads(data.decode())
            name = obj["name"]
            pubkey = obj["pubkey"].encode()
            if name != username and name not in peers:
                peers[name] = (addr[0], pubkey)
                save_peer(name, pubkey)
        except:
            pass

# === MESSAGE I/O ===
def chat_file(peer):
    names = sorted([username, peer])
    return os.path.join(MSG_DIR, f"{names[0]}_{names[1]}.json")

def load_chat(peer):
    path = chat_file(peer)
    if not os.path.exists(path): return []
    with open(path, 'r') as f:
        return json.load(f)

def save_chat(peer, chat):
    with open(chat_file(peer), 'w') as f:
        json.dump(chat, f, indent=2)

def encrypt_for(peer, text):
    pub = load_peer(peer)
    if not pub: return None
    return PKCS1_OAEP.new(pub).encrypt(text.encode()).hex()

def decrypt_msg(hex_data):
    try:
        raw = bytes.fromhex(hex_data)
        return priv_cipher.decrypt(raw).decode()
    except:
        return "[Encrypted]"

# === MESSAGE SENDER ===
def send_to_peer(peer_name, hex_data):
    ip = peers.get(peer_name, (None,))[0]
    if not ip:
        print(f"Can't find IP for {peer_name}")
        return
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, MSG_PORT))
        packet = json.dumps({
            "sender": username,
            "text": hex_data,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M")
        }).encode()
        s.sendall(packet)
        s.close()
    except:
        print("Failed to send message.")

# === MESSAGE RECEIVER ===
def recv_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', MSG_PORT))
    sock.listen()
    while True:
        conn, addr = sock.accept()
        data = conn.recv(8192)
        try:
            msg = json.loads(data.decode())
            sender = msg["sender"]
            chat = load_chat(sender)
            chat.append(msg)
            save_chat(sender, chat)
        except:
            pass
        conn.close()

# === UI ===
def chat_with(peer):
    while True:
        os.system("cls" if os.name == "nt" else "clear")
        chat = load_chat(peer)
        for m in chat:
            label = "You" if m['sender'] == username else peer
            text = decrypt_msg(m['text'])
            print(f"[{m['time']}] {label}: {text}")
        msg = input("\nMessage (/exit): ").strip()
        if msg == "/exit": break
        enc = encrypt_for(peer, msg)
        if not enc:
            print("Missing public key for peer.")
            time.sleep(2)
            continue
        chat.append({
            "sender": username,
            "text": enc,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M")
        })
        save_chat(peer, chat)
        send_to_peer(peer, enc)

# === STARTUP ===
threading.Thread(target=broadcast_presence, daemon=True).start()
threading.Thread(target=listen_for_peers, daemon=True).start()
threading.Thread(target=recv_server, daemon=True).start()

# === MAIN MENU ===
def main():
    while True:
        print("\n=== Welcome to @Chat | Encrypted LAN Messenger ===")
        print("Online users:")
        for name, (ip, _) in peers.items():
            print(f" - {name} ({ip})")
        print("Commands:\n /chat [name]\n /exit")
        cmd = input("> ").strip()
        if cmd == "/exit":
            break
        elif cmd.startswith("/chat "):
            target = cmd.split(" ", 1)[1].strip()
            chat_with(target)

if __name__ == "__main__":
    main()