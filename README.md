# Where Winds Meet (WWM) API Explorer

A premium, high-performance API Explorer and Backend Service for the "Where Winds Meet" game. This project provides a bridge between game data and external applications (like Discord bots) while offering a beautiful web interface for manual lookups.

## 🚀 Features

- **Player Lookup**: Search for players by **Number ID** or **Nickname** across multiple game regions (SEA & CN).
- **Club Search**: Query global guilds, martial arts clubs, and player associations.
- **Auto-Server Search**: Intelligent parallel searching across all known server regions with extremely low latency.
- **Face Plan Converter**: Migration tool for legacy face plan data.
- **Premium UI**: iOS-style glassmorphic dashboard with real-time JSON syntax highlighting and mobile-first design.
- **Data Enrichment**: Fetching extra details including fashion scores, cover images, online status, and character portraits.

## 🛠 Tech Stack

- **Backend**: Node.js, Express.js
- **Data Protocol**: Msgpack (MessagePack) integration for game-native communication.
- **Networking**: Custom DNS caching and HTTPS agent for optimized API calls.
- **Frontend**: Tailwind CSS, Vanilla JavaScript, Glassmorphism Aesthetics.

## 📦 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/KhoaDayy/find-api.git
   cd find-api
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure your session:
   Create a `session.txt` file in the root directory and paste your valid game session key.

4. Start the server:
   ```bash
   node player_api.js
   ```

## 🖥 API Endpoints

- **GET `/lookup?name={nickname}`**: Search player by name.
- **GET `/lookup?id={number_id}`**: Search player by ID.
- **GET `/club_search?name={club_name}`**: Search for a club/guild.
- **GET `/id?keyword={text}`**: Intelligent redirect based on input type (Numeric ID vs Name).

## 📂 Project Structure

- `player_api.js`: The heart of the project. Proxies and formats game API requests.
- `index.html`: The visual API Explorer dashboard.
- `api_sniffer.py`: Diagnostic tool for capturing network traffic.
- `hook/`: DLL and Injector files for game interaction analysis.
- `src/`: Source code for the GameHook components.

## ⚠️ Disclaimer

This tool is designed for educational and data exploration purposes. Please ensure compliance with the game's terms of service.

---
Developed for the **Where Winds Meet** community.
