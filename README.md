<div align="center">

# VOIDTRACE 🦉

**High-Velocity IP Intelligence & Reputation Terminal**

[![Vite](https://img.shields.io/badge/Vite-B73BFE?style=for-the-badge&logo=vite&logoColor=FFD62E)](https://vitejs.dev/)
[![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)](https://reactjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![TailwindCSS](https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)

</div>

---

## ⚡ Overview

**Voidtrace** is a lightning-fast, terminal-emulated web application designed for comprehensive IP address reconnaissance. It aggregates intelligence from multiple security vendors in parallel, delivering deep insights into an IP's geographic origin, ISP, open ports, recent vulnerabilities, and malicious reputation.

Designed to be integrated into the broader **[0TRACE](https://github.com/athx1337/0trace)** suite, Voidtrace runs seamlessly as a standalone web terminal with heavily stylized UI typing animations.

### 🔍 Intelligence Modules
Voidtrace concurrently queries the following APIs to build a unified reputation profile:
- 🌎 **ip-api** & **ipapi**: Geolocation, ASN, ISP, VPN/Tor/Proxy detection.
- 📡 **Shodan InternetDB**: Open ports, hostnames, and known CVEs.
- 🚨 **AbuseIPDB**: Abuse confidence scores and spam reports.
- 👽 **AlienVault OTX**: Pulse counts and associated malware families.
- 🔊 **GreyNoise**: Internet background noise and scanner classification.

## 🚀 Live Demo
**Frontend:** https://voidtrace.vercel.app  
*Note: The frontend is statically hosted on Vercel and routes directly to the Python backend deployed securely on Railway.*

---

## 🛠️ Installation & Setup

### Prerequisites
- Node.js (v18+)
- Python 3.10+

### 1. Backend Setup
Navigate to the `backend` directory and install the requirements:
```bash
cd backend
pip install -r requirements.txt
```

Create a `.env` file referencing `.env.example`:
```ini
ABUSEIPDB_KEY=your_key_here
OTX_API_KEY=your_key_here
GREYNOISE_KEY=your_community_key_here # Optional — defaults to unauthenticated API 
```
Run the FastAPI server locally:
```bash
uvicorn main:app --reload --port 8001
```

### 2. Frontend Setup
Navigate to the `frontend` directory:
```bash
cd frontend
npm install
```

Configure your environment variables properly:
```ini
VITE_API_URL=http://localhost:8001
```

Start the Vite development server:
```bash
npm run dev
```

---

## ☁️ Deployment

- **Backend (Railway):** Point your Railway project to the `backend` root directory using Railpack. Use the custom start command `uvicorn main:app --host 0.0.0.0 --port $PORT` to bind correctly.
- **Frontend (Vercel):** Point Vercel to `frontend`. Set `VITE_API_URL` to your deployed Railway domain. Strict `Cache-Control` headers are dynamically enforced via the included `vercel.json` to prevent aggressive mobile edge caching.

---
<div align="center">
<i>A part of the 0TRACE framework. Designed by athx1337.</i>
</div>
