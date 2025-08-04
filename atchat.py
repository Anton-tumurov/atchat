import os, socket, time, json, threading
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from getpass import getpass

# === SETUP PATHS ===
MSG_DIR = "messages"
KEY_DIR = "keys"
PEER_DIR = "peers"
PORT = 50002
BROADCAST_IP = '255.255.255.255'

os.makedirs(MSG_DIR, exist_ok=True)
os.makedirs(KEY_DIR, exist_ok=True)
os.makedirs(PEER_DIR, exist_ok=True)

# === PLACEHOLDER LOGIN FUNCTION ===
def login():
    Username = input("Enter Username: ") # replace with real auth later
    return Username

username = login()

# === RSA KEY MANAGEMENT ===
PRIV_KEY_FILE = os.path.join(KEY_DIR, "private.pem")
PUB_KEY_FILE  = os.path.join(KEY_DIR, "public.pem")

if not os.path.exists(PRIV_KEY_FILE):
    key = RSA.generate(4096)
    with open(PRIV_KEY_FILE, 'wb') as f:
        f.write(key.export_key())
    with open(PUB_KEY_FILE, 'wb') as f:
        f.write(key.publickey().export_key())

with open(PRIV_KEY_FILE, 'rb') as f:
    private_key = RSA.import_key(f.read())
private_cipher = PKCS1_OAEP.new(private_key)

with open(PUB_KEY_FILE, 'rb') as f:
    my_public_key = f.read()

# === PEER MANAGEMENT ===
peers = {}  # name -> (ip, pubkey)

def save_peer(name, pubkey):
    path = os.path.join(PEER_DIR, f"{name}.pem")
    with open(path, 'wb') as f:
        f.write(pubkey)

def load_peer(name):
    path = os.path.join(PEER_DIR, f"{name}.pem")
    if os.path.exists(path):
        with open(path, 'rb') as f:
            return RSA.import_key(f.read())
    return None

# === BROADCAST PRESENCE ===
def broadcast_presence():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    while True:
        packet = json.dumps({
            "name": username,
            "pubkey": my_public_key.decode()
        }).encode()
        sock.sendto(packet, (BROADCAST_IP, PORT))
        time.sleep(5)

def listen_for_peers():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', PORT))
    while True:
        data, addr = sock.recvfrom(8192)
        try:
            obj = json.loads(data.decode())
            name = obj["name"]
            if name != username:
                if name not in peers:
                    pubkey = obj["pubkey"].encode()
                    peers[name] = (addr[0], pubkey)
                    save_peer(name, pubkey)
        except:
            pass

threading.Thread(target=broadcast_presence, daemon=True).start()
threading.Thread(target=listen_for_peers, daemon=True).start()

# === MESSAGE HANDLING ===
def get_chat_file(partner):
    names = sorted([username, partner])
    return os.path.join(MSG_DIR, f"{names[0]}_{names[1]}.json")

def load_chat(partner):
    path = get_chat_file(partner)
    if not os.path.exists(path):
        return []
    with open(path, 'r') as f:
        return json.load(f)

def save_chat(partner, messages):
    path = get_chat_file(partner)
    with open(path, 'w') as f:
        json.dump(messages, f, indent=2)

def encrypt_for(peer_name, plaintext):
    pubkey = load_peer(peer_name)
    if not pubkey:
        return None
    cipher = PKCS1_OAEP.new(pubkey)
    return cipher.encrypt(plaintext.encode()).hex()

def decrypt_msg(hex_data):
    try:
        encrypted = bytes.fromhex(hex_data)
        return private_cipher.decrypt(encrypted).decode()
    except:
        return "[Encrypted]"

def chat_with(partner):
    while True:
        os.system("cls" if os.name == "nt" else "clear")
        chat = load_chat(partner)
        for m in chat:
            if m['sender'] == username:
                print(f"[{m['time']}] You: {decrypt_msg(m['text'])}")
            else:
                print(f"[{m['time']}] {partner}: {decrypt_msg(m['text'])}")
        msg = input("\nMessage (/exit): ").strip()
        if msg == "/exit":
            break
        if msg:
            encrypted = encrypt_for(partner, msg)
            if not encrypted:
                print("Cannot find public key for this user.")
                continue
            chat.append({
                "sender": username,
                "text": encrypted,
                "time": datetime.now().strftime("%Y-%m-%d %H:%M")
            })
            save_chat(partner, chat)

# === MAIN MENU ===
def main():
    while True:
        print("\n=== Encrypted LAN Chat ===")
        print("Known users:")
        for name in peers:
            print(f"- {name}")
        print("\nCommands:\n  /chat [name]\n  /exit")
        cmd = input("> ").strip()
        if cmd == "/exit":
            break
        elif cmd.startswith("/chat "):
            target = cmd.split(" ", 1)[1].strip()
            chat_with(target)

if __name__ == "__main__":
    main()