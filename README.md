<p align="center">
  <picture>
    <img src="assets/Logo.png" alt="@Chat Logo" width="300">
  </picture>
</p>

**@Chat** is a lightweight, modern, peer-to-peer chat application designed for local network communication, such as classrooms or small workgroups. It mimics the user experience of modern messaging apps like WhatsApp while functioning without the need for a centralized server.

## Features

- 🌐 Local P2P chat using LAN broadcast
- 🔐 End-to-end encrypted messages
- 👥 Group chats ("chat rooms") using room codes instead of IPs
- 🖥️ GUI that resembles a modern messaging app
- 🪪 Anonymous login or nicknames
- 💻 Easy setup – no servers or external services required

## How it works

When a user creates a chat room, they are assigned a room code which other users on the same network can use to join. Messages are broadcasted over the local network and only received by participants in that room.

## Requirements

- Python 3.9+
- Tkinter (usually comes preinstalled with Python)
- `cryptography` package for encryption

Install dependencies with:

```bash
pip install -r requirements.txt
```

## Run the App

```bash
python main.py
```

## Notes

- Works best on the same Wi-Fi or LAN network.
- School or workplace firewalls may block UDP broadcast – check with your network administrator.

## License

MIT License. See [LICENSE](LICENSE) for details.

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md)
