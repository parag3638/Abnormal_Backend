const fs = require('fs');
const path = require('path');
const multer = require('multer');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const router = require('express').Router();
require('dotenv').config();

// Encryption settings
const algorithm = 'aes-256-cbc';
const keyLength = 32;
const ivLength = 16;
const iterations = 100000;

const verifyToken = require('../auth/middlewares/authMiddleware');
const authorizeRoles = require('../auth/middlewares/roleMiddlewares');

module.exports = function () {

    // ✅ **Encrypt & Track File Owner**
    router.post('/encrypt', verifyToken, authorizeRoles('admin', 'user'), upload.single('file'), (req, res) => {

        const token = req.headers.authorization?.split(' ')[1]; // Extract token from `Bearer <token>`

        if (!token) {
            return res.status(401).json({ error: 'Unauthorized. No token provided.' });
        }

        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const ownerEmail = decoded.email; // Get user email from JWT

            if (!req.file) {
                return res.status(400).json({ error: 'No file uploaded.' });
            }

            const password = req.body.password;
            const inputPath = req.file.path;
            const outputPath = path.join(__dirname, 'encrypted', `${req.file.filename}.enc`);

            const salt = crypto.randomBytes(16);
            const key = deriveKey(password, salt);
            const iv = crypto.randomBytes(ivLength);

            const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
            const fileData = fs.readFileSync(inputPath);
            const encryptedData = Buffer.concat([cipher.update(fileData), cipher.final()]);

            if (!fs.existsSync(path.join(__dirname, 'encrypted'))) {
                fs.mkdirSync(path.join(__dirname, 'encrypted'), { recursive: true });
            }

            fs.writeFileSync(outputPath, Buffer.concat([salt, iv, encryptedData]));
            fs.unlinkSync(inputPath); // Delete original file

            // Save file owner mapping
            let fileMap = getFileMap();
            const newFileEntry = {
                id: fileMap.length + 1,
                owner: ownerEmail,
                original_filename: req.file.originalname,
                encrypted_filename: path.basename(outputPath),
                upload_timestamp: new Date().toISOString()
            };
            fileMap.push(newFileEntry);
            saveFileMap(fileMap);

            res.json({ message: 'File encrypted successfully!', file: newFileEntry });
        } catch (error) {
            console.error('Encryption error:', error.message);
            res.status(500).json({ error: 'Server error' });
        }
    });

    // ✅ API: Decrypt File (Fetch from `/encrypted`, Save to `/decrypted`)
    router.post("/decrypt", verifyToken, authorizeRoles('admin', 'user'), (req, res) => {
        const token = req.headers.authorization?.split(" ")[1]; // Extract token

        if (!token) {
            return res.status(401).json({ error: "Unauthorized. No token provided." });
        }

        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const userEmail = decoded.email; // Extract email from token

            const { filename, password } = req.body;

            if (!filename || !password) {
                return res.status(400).json({ error: "Filename and password are required." });
            }

            const encryptedFilePath = path.join(__dirname, "encrypted", filename);
            const decryptedFilePath = path.join(__dirname, "decrypted", filename.replace(".enc", ""));

            if (!fs.existsSync(encryptedFilePath)) {
                return res.status(404).json({ error: "Encrypted file not found." });
            }

            // ✅ Read encrypted file
            const fileData = fs.readFileSync(encryptedFilePath);
            const salt = fileData.slice(0, 16);
            const iv = fileData.slice(16, 32);
            const encryptedData = fileData.slice(32);

            const key = deriveKey(password, salt);
            const decipher = crypto.createDecipheriv(algorithm, key, iv);
            const decryptedData = Buffer.concat([decipher.update(encryptedData), decipher.final()]);

            // ✅ Ensure decrypted folder exists
            if (!fs.existsSync(path.join(__dirname, "decrypted"))) {
                fs.mkdirSync(path.join(__dirname, "decrypted"), { recursive: true });
            }

            // ✅ Write decrypted file
            fs.writeFileSync(decryptedFilePath, decryptedData);

            res.json({
                message: "File decrypted successfully!",
                decryptedFile: path.basename(decryptedFilePath),
                downloadLink: `/decrypted/${path.basename(decryptedFilePath)}`,
            });
        } catch (error) {
            console.error("Decryption error:", error.message);
            res.status(500).json({ error: "Decryption failed", details: error.message });
        }
    });


    // ✅ API: Download Encrypted File
    router.get('/encrypted/:filename', (req, res) => {
        const filePath = path.join(__dirname, 'encrypted', req.params.filename);
        if (fs.existsSync(filePath)) {
            res.sendFile(filePath);
        } else {
            res.status(404).json({ error: 'File not found' });
        }
    });

    // 📂 API Route: Serve Decrypted Files
    router.get('/decrypted/:filename', (req, res) => {
        const filePath = path.join(__dirname, 'decrypted', req.params.filename);

        if (fs.existsSync(filePath)) {
            res.sendFile(filePath);
        } else {
            res.status(404).json({ error: 'File not found' });
        }
    });


    // ✅ GET API to fetch user's encrypted files
    router.get("/my-files", (req, res) => {
        const token = req.headers.authorization?.split(" ")[1]; // Extract token

        if (!token) {
            return res.status(401).json({ error: "Unauthorized. No token provided." });
        }

        try {
            // Verify JWT token
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const userEmail = decoded.email; // Extract email from token

            // Retrieve files belonging to this user
            const fileMap = getFileMap();
            const userFiles = fileMap.filter(file => file.owner === userEmail);

            res.json({ files: userFiles });
        } catch (error) {
            console.error("Error fetching files:", error.message);
            res.status(500).json({ error: "Server error" });
        }
    });

    return router;
};



// Multer configuration (uploads any file type)
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = path.join(__dirname, 'uploads');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        cb(null, `${Date.now()}-${file.originalname}`);
    }
});
const upload = multer({ storage });

// Function to derive encryption key
function deriveKey(password, salt) {
    return crypto.pbkdf2Sync(password, salt, iterations, keyLength, 'sha256');
}


const fileMapPath = path.join(__dirname, './fileMap.json');

// Helper to read file mappings
function getFileMap() {
    if (!fs.existsSync(fileMapPath)) {
        fs.writeFileSync(fileMapPath, JSON.stringify([]));
    }
    return JSON.parse(fs.readFileSync(fileMapPath, 'utf8'));
}

// Helper to save file mappings
function saveFileMap(fileMap) {
    fs.writeFileSync(fileMapPath, JSON.stringify(fileMap, null, 2));
}

