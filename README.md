# Abnormal_Backend

# Secure File Sharing API (Backend)

## Overview
This is the backend service for a **secure file-sharing web application** that provides **user authentication, multi-factor authentication (MFA), file encryption, and role-based access control (RBAC)**. It ensures **secure storage and retrieval** of files with controlled access. I have used files in local as DB for demo and handiness.

## Tech Stack
- **Node.js + Express.js**
- **PostgreSQL / MongoDB**
- **JWT Authentication**
- **AES-256 Encryption**
- **Multer for File Uploads**


## Folder Structure
```
backend/
│── src/
│   ├── controllers/   # API Controllers
│   ├── middlewares/   # Authentication & Security Middleware
│   ├── models/        # Database Models
│   ├── routes/        # API Routes
│   ├── services/      # Business Logic
│   ├── utils/         # Encryption & Helper Functions
│── config/            # Configuration Files
│── .env               # Environment Variables
│── package.json       # Dependencies
│── server.js          # Main Server File
│── README.md          # Documentation
```

## Setup
### Prerequisites
- **Node.js v18+**
- **PostgreSQL / MongoDB**
- **Docker & Docker-Compose**
- **AWS / GCP Storage credentials (optional)**

### Installation
1. **Clone the Repository**
```bash
git clone github_url
```

2. **Install Dependencies**
```bash
npm install
```

3. **Configure Environment Variables**
Create a `.env` file in the `backend` directory:
```
RESEND_API_KEY=your_resend_key
JWT_SECRET=your_secret_key
ENCRYPTION_KEY=your_encryption_key
```

4. **Start the Backend Server**
```bash
node index.js
```
The backend will run at `http://localhost:9000`

## API Documentation

### Authentication APIs

#### Register a User
```
POST /api/auth/register
```
**Request Body:**
```json
{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "securePassword",
  "role": "user"
}
```
**Response:**
```json
{
  "message": "User registered successfully",
  "token": "your_jwt_token"
}
```

#### Login with MFA
```
POST /api/auth/login
```
**Request Body:**
```json
{
  "email": "john@example.com",
  "password": "securePassword",
  "otp": "123456"
}
```
**Response:**
```json
{
  "token": "your_jwt_token",
  "message": "Login successful"
}
```

#### Generate MFA OTP
```
POST /api/auth/generate-otp
```
**Headers:**
```
Authorization: Bearer your_jwt_token
```
**Response:**
```json
{
  "message": "OTP sent to registered email"
}
```

#### Verify MFA OTP
```
POST /api/auth/verify-otp
```
**Request Body:**
```json
{
  "otp": "123456"
}
```
**Response:**
```json
{
  "message": "OTP verified successfully"
}
```

### File Management APIs

#### Upload a File (Encrypted)
```
POST /api/files/upload
```
**Headers:**
```
Authorization: Bearer your_jwt_token
Content-Type: multipart/form-data
```
**Form Data:**
- `file`: (Binary File)

**Response:**
```json
{
  "message": "File uploaded successfully",
  "fileId": "12345"
}
```

#### Download a File (Decryption on Request)
```
GET /api/files/download/:fileId
```
**Headers:**
```
Authorization: Bearer your_jwt_token
```
**Response:**
- Returns the **decrypted file**.

#### Share File with Expirable Link
```
POST /api/files/share
```
**Headers:**
```
Authorization: Bearer your_jwt_token
```
**Request Body:**
```json
{
  "fileId": "12345",
  "expiresIn": "24h"
}
```
**Response:**
```json
{
  "message": "Shared successfully",
  "link": "https://yourdomain.com/file/12345"
}
```


## Contact
For any questions, feel free to **open an issue** or contact me at:
parag.singh528@gmail.com