# 🌟 BrahmAIstra Hackathon Platform

<div align="center">

![BrahmAIstra Logo](https://img.shields.io/badge/BrahmAIstra-Innovation%20Platform-orange?style=for-the-badge&logo=react)

**"Innovation Starts, Where Hesitation Ends!"**

[![Deploy Frontend](https://img.shields.io/badge/Deploy%20Frontend-Vercel-black?style=flat-square&logo=vercel)](https://vercel.com/new/clone?repository-url=https://github.com/shivam-pandey/brahmastra-hackathon/tree/main/frontend)
[![Deploy Backend](https://img.shields.io/badge/Deploy%20Backend-Railway-purple?style=flat-square&logo=railway)](https://railway.app/template/your-template-id)
[![Security Score](https://img.shields.io/badge/Security%20Score-8.5%2F10-green?style=flat-square&logo=shield)](https://github.com/shivam-pandey/brahmastra-hackathon)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](https://opensource.org/licenses/MIT)

</div>

---

## 🚀 **Quick Deploy (5 Minutes)**

### **Option 1: One-Click Deploy**

| Platform | Deploy Now | Free Tier |
|----------|------------|-----------|
| **Frontend** | [![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/shivam-pandey/brahmastra-hackathon/tree/main/frontend) | ✅ Yes |
| **Backend** | [![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new/template/your-template) | ✅ $5 Credit |

### **Option 2: Manual Setup**

```bash
# 1. Clone repository
git clone https://github.com/shivam-pandey/brahmastra-hackathon.git
cd brahmastra-hackathon

# 2. Set up backend
cd backend
cp .env.example .env
# Edit .env with your MongoDB URI and JWT secrets
npm install
npm start

# 3. Set up frontend
cd ../frontend
npm install
npm start

# 4. Deploy using our script
chmod +x deploy.sh
./deploy.sh --quick
