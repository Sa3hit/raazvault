// ═══════════════════════════════════════════════════════════════════════════════
//  RaazVault — Zero-Knowledge Encrypted File Sharing Server
// ═══════════════════════════════════════════════════════════════════════════════
//
//  HOW IT WORKS (read this for your project understanding):
//  ─────────────────────────────────────────────────────────
//  1. The user picks a file in the browser.
//  2. The BROWSER encrypts the file using AES-256-GCM (Web Crypto API).
//     → The server NEVER sees the plaintext file. This is "zero-knowledge".
//  3. The encrypted blob is uploaded to this server via POST /api/upload.
//  4. The server stores the encrypted blob on disk + metadata (IV, TTL, views).
//  5. A unique "Raaz link" is generated. The decryption key is in the URL #fragment,
//     which is NEVER sent to the server (browser security feature).
//  6. The receiver opens the link → browser downloads the encrypted blob from the
//     server → decrypts it locally using the key from the URL → downloads plaintext.
//  7. After max views or TTL expiry, the server auto-deletes the file.
//
//  TECHNOLOGIES USED:
//  ─────────────────
//  • Node.js       — JavaScript runtime that runs on the server (not in browser)
//  • Express.js    — Web framework that handles HTTP requests (GET, POST, etc.)
//  • Multer        — Middleware for handling file uploads (multipart/form-data)
//  • UUID          — Generates unique random IDs for each uploaded file
//  • Helmet        — Adds security HTTP headers automatically
//  • Rate Limiter  — Prevents abuse by limiting how many requests per IP per minute
//  • bcryptjs      — Hashes passwords so they're never stored in plain text
//  • JWT           — JSON Web Tokens for stateless user authentication
//  • cookie-parser — Reads cookies sent by the browser (used for auth tokens)
//  • fs (built-in) — Node.js file system module for reading/writing files to disk
//  • path (built-in) — Handles file/directory paths safely across OS
//
// ═══════════════════════════════════════════════════════════════════════════════

const express = require('express');
const http = require('http');
const { Server: SocketIO } = require('socket.io');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const path = require('path');

// ─── CONFIG ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const UPLOADS_DIR = path.join(__dirname, 'uploads');       // Where encrypted blobs are stored
const USERS_FILE = path.join(__dirname, 'users.json');     // Simple JSON-based user storage
const JWT_SECRET = process.env.JWT_SECRET || 'raazvault-local-dev-secret-key-2026';
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50 MB limit (free tier friendly)

// ─── ENSURE DIRECTORIES AND FILES EXIST ──────────────────────────────────────
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]');

// ─── CREATE EXPRESS APP + HTTP SERVER ────────────────────────────────────────
const app = express();
const server = http.createServer(app);
const io = new SocketIO(server, { cors: { origin: '*' } });

// Trust proxy — required when behind Render's reverse proxy (for rate limiting, secure cookies)
if (IS_PRODUCTION) app.set('trust proxy', 1);

// ─── MIDDLEWARE EXPLAINED ─────────────────────────────────────────────────────
// Middleware = functions that run BEFORE your route handlers.
// They process/modify the request, add security, parse data, etc.

// Helmet: Adds security headers (X-Content-Type-Options, X-Frame-Options, etc.)
// These headers tell browsers to be more strict about what they allow.
app.use(helmet({
  contentSecurityPolicy: false, // Disabled because our inline styles/scripts need to work
  crossOriginEmbedderPolicy: false
}));

// JSON parser: Allows the server to read JSON data sent in request bodies
app.use(express.json());

// URL-encoded parser: Allows reading form data (like name=value pairs)
app.use(express.urlencoded({ extended: true }));

// Cookie parser: Reads cookies from the browser (we store JWT tokens in cookies)
app.use(cookieParser());

// Static file server: Serves our HTML/CSS/JS files from the "public" folder
// When someone visits http://localhost:3000, Express sends public/index.html
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiting: Prevents abuse. Max 30 uploads per IP per 15 minutes.
const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minute window
  max: 30,
  message: { ok: false, error: 'Too many uploads. Please try again later.' },
  standardHeaders: true
});

// ─── MULTER SETUP (FILE UPLOAD HANDLING) ──────────────────────────────────────
// Multer handles "multipart/form-data" which is the format browsers use
// to send files. We configure WHERE to store files and size limits.
const storage = multer.diskStorage({
  destination: UPLOADS_DIR,
  filename: (_req, _file, cb) => {
    // Generate a unique filename using UUID so files never collide
    cb(null, uuidv4() + '.raaz');
  }
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  USER AUTHENTICATION (Signup / Login / JWT)
// ═══════════════════════════════════════════════════════════════════════════════
//
//  HOW AUTH WORKS:
//  1. User signs up → password is HASHED with bcrypt (never stored as plain text)
//  2. User logs in → password is compared against the hash
//  3. If correct, server creates a JWT (JSON Web Token) — a signed token containing
//     the user's ID and email. This token is sent as a cookie.
//  4. On future requests, the server reads the cookie, verifies the JWT signature,
//     and knows who the user is — without needing sessions or a database.
//
// ═══════════════════════════════════════════════════════════════════════════════

// Helper: Read all users from the JSON file
function getUsers() {
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf-8'));
  } catch {
    return [];
  }
}

// Helper: Save users array to the JSON file
function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// ─── SIGNUP ────────────────────────────────────────────────────────────────────
// POST /api/auth/signup
// Body: { name, email, password }
// Creates a new user account with a hashed password
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validate inputs
    if (!name || !email || !password) {
      return res.json({ ok: false, error: 'All fields are required.' });
    }
    if (password.length < 6) {
      return res.json({ ok: false, error: 'Password must be at least 6 characters.' });
    }

    const users = getUsers();

    // Check if email already exists
    if (users.find(u => u.email === email)) {
      return res.json({ ok: false, error: 'Email already registered.' });
    }

    // Hash the password using bcrypt (10 salt rounds)
    // bcrypt adds random "salt" to prevent rainbow table attacks
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = {
      id: uuidv4(),
      name,
      email,
      password: hashedPassword, // NEVER store plain text passwords!
      createdAt: new Date().toISOString()
    };

    users.push(user);
    saveUsers(users);

    // Create JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email, name: user.name },
      JWT_SECRET,
      { expiresIn: '7d' } // Token valid for 7 days
    );

    // Set token as HTTP-only cookie (more secure than localStorage)
    res.cookie('token', token, {
      httpOnly: true,   // JavaScript can't read this cookie (XSS protection)
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
      sameSite: 'lax',
      secure: IS_PRODUCTION  // HTTPS only in production (Render uses HTTPS)
    });

    res.json({ ok: true, user: { id: user.id, name: user.name, email: user.email } });
  } catch (err) {
    console.error('Signup error:', err);
    res.json({ ok: false, error: 'Signup failed.' });
  }
});

// ─── LOGIN ─────────────────────────────────────────────────────────────────────
// POST /api/auth/login
// Body: { email, password }
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.json({ ok: false, error: 'Email and password are required.' });
    }

    const users = getUsers();
    const user = users.find(u => u.email === email);

    if (!user) {
      return res.json({ ok: false, error: 'Invalid email or password.' });
    }

    // bcrypt.compare checks the plain password against the stored hash
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.json({ ok: false, error: 'Invalid email or password.' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, name: user.name },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000,
      sameSite: 'lax',
      secure: IS_PRODUCTION
    });

    res.json({ ok: true, user: { id: user.id, name: user.name, email: user.email } });
  } catch (err) {
    console.error('Login error:', err);
    res.json({ ok: false, error: 'Login failed.' });
  }
});

// ─── LOGOUT ────────────────────────────────────────────────────────────────────
app.post('/api/auth/logout', (_req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

// ─── GET CURRENT USER ──────────────────────────────────────────────────────────
// GET /api/auth/me — returns the logged-in user's info (from the JWT cookie)
app.get('/api/auth/me', (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.json({ ok: false, error: 'Not logged in.' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ ok: true, user: { id: decoded.id, name: decoded.name, email: decoded.email } });
  } catch {
    res.json({ ok: false, error: 'Invalid or expired token.' });
  }
});


// ═══════════════════════════════════════════════════════════════════════════════
//  FILE SHARING API (Upload / Metadata / Download)
// ═══════════════════════════════════════════════════════════════════════════════
//
//  FLOW:
//  ─────
//  1. POST /api/upload     → Receives encrypted blob + metadata, stores on disk
//  2. GET  /api/file/:id/meta     → Returns metadata (IV, salt, name, views left)
//  3. GET  /api/file/:id/download → Streams encrypted blob, decrements view count
//
//  The server NEVER has the decryption key. It only stores:
//  • The encrypted blob (useless without the key)
//  • The IV (initialization vector) needed for AES-GCM decryption
//  • The salt (if password was used for key derivation)
//  • Metadata: original filename, MIME type, file size, views, expiry time
//
// ═══════════════════════════════════════════════════════════════════════════════

// ─── UPLOAD ENCRYPTED FILE ─────────────────────────────────────────────────────
// POST /api/upload
// Expects multipart form: file (encrypted blob) + metadata fields
app.post('/api/upload', uploadLimiter, upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ ok: false, error: 'No file uploaded.' });
    }

    const { originalName, mime, originalSize, iv, salt, ttlSeconds, maxViews } = req.body;

    // The file ID is the filename without extension (UUID we generated in multer)
    const fileId = path.parse(req.file.filename).name;

    // Create metadata JSON alongside the encrypted file
    const metadata = {
      id: fileId,
      originalName: originalName || 'unknown',
      mime: mime || 'application/octet-stream',
      originalSize: parseInt(originalSize) || 0,
      iv: iv || '',            // Initialization Vector for AES-GCM
      salt: salt || '',        // Salt for PBKDF2 key derivation (if password used)
      maxViews: parseInt(maxViews) || 1,
      viewsUsed: 0,
      ttlSeconds: parseInt(ttlSeconds) || 3600,
      createdAt: Date.now(),
      expiresAt: Date.now() + (parseInt(ttlSeconds) || 3600) * 1000,
      // Track who uploaded (if logged in)
      uploadedBy: null
    };

    // Check if user is logged in (optional — files can be uploaded anonymously)
    const token = req.cookies ? req.cookies.token : null;
    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        metadata.uploadedBy = decoded.email;
      } catch { /* anonymous upload */ }
    }

    // Save metadata as JSON file next to the encrypted blob
    const metaPath = path.join(UPLOADS_DIR, fileId + '.json');
    fs.writeFileSync(metaPath, JSON.stringify(metadata, null, 2));

    console.log(`[UPLOAD] File ${fileId} stored (${(req.file.size / 1024 / 1024).toFixed(2)} MB encrypted)`);

    res.json({ ok: true, id: fileId });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ ok: false, error: 'Upload failed.' });
  }
});

// ─── GET FILE METADATA ─────────────────────────────────────────────────────────
// GET /api/file/:id/meta
// Returns metadata needed for decryption (IV, salt, filename, MIME type)
// Does NOT return the encrypted file itself
app.get('/api/file/:id/meta', (req, res) => {
  const fileId = req.params.id;
  const metaPath = path.join(UPLOADS_DIR, fileId + '.json');

  if (!fs.existsSync(metaPath)) {
    return res.json({ ok: false, error: 'File not found or expired.' });
  }

  const metadata = JSON.parse(fs.readFileSync(metaPath, 'utf-8'));

  // Check if expired by time
  if (Date.now() > metadata.expiresAt) {
    deleteFile(fileId);
    return res.json({ ok: false, error: 'File has expired and been destroyed.' });
  }

  // Check if view limit exceeded
  if (metadata.viewsUsed >= metadata.maxViews) {
    deleteFile(fileId);
    return res.json({ ok: false, error: 'View limit reached. File has been destroyed.' });
  }

  // Return metadata (but NOT the encryption key — server doesn't have it!)
  res.json({
    ok: true,
    originalName: metadata.originalName,
    mime: metadata.mime,
    originalSize: metadata.originalSize,
    iv: metadata.iv,
    salt: metadata.salt,
    viewsLeft: metadata.maxViews - metadata.viewsUsed,
    expiresAt: metadata.expiresAt
  });
});

// ─── DOWNLOAD ENCRYPTED FILE ──────────────────────────────────────────────────
// GET /api/file/:id/download
// Streams the encrypted blob to the client. Decrements view counter.
app.get('/api/file/:id/download', (req, res) => {
  const fileId = req.params.id;
  const metaPath = path.join(UPLOADS_DIR, fileId + '.json');
  const filePath = path.join(UPLOADS_DIR, fileId + '.raaz');

  if (!fs.existsSync(metaPath) || !fs.existsSync(filePath)) {
    return res.status(404).json({ ok: false, error: 'File not found or expired.' });
  }

  const metadata = JSON.parse(fs.readFileSync(metaPath, 'utf-8'));

  // Check expiry
  if (Date.now() > metadata.expiresAt) {
    deleteFile(fileId);
    return res.status(410).json({ ok: false, error: 'File has expired.' });
  }

  // Check views
  if (metadata.viewsUsed >= metadata.maxViews) {
    deleteFile(fileId);
    return res.status(410).json({ ok: false, error: 'View limit reached.' });
  }

  // Increment view counter and save
  metadata.viewsUsed += 1;
  fs.writeFileSync(metaPath, JSON.stringify(metadata, null, 2));

  console.log(`[DOWNLOAD] File ${fileId} — view ${metadata.viewsUsed}/${metadata.maxViews}`);

  // If this was the last allowed view, schedule deletion
  if (metadata.viewsUsed >= metadata.maxViews) {
    setTimeout(() => deleteFile(fileId), 5000); // Delete after 5 seconds (give time to finish download)
  }

  // Stream the encrypted file to the client
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${fileId}.raaz"`);
  fs.createReadStream(filePath).pipe(res);
});


// ═══════════════════════════════════════════════════════════════════════════════
//  FILE CLEANUP (Auto-Destruct)
// ═══════════════════════════════════════════════════════════════════════════════

// Delete a file and its metadata from disk
function deleteFile(fileId) {
  const filePath = path.join(UPLOADS_DIR, fileId + '.raaz');
  const metaPath = path.join(UPLOADS_DIR, fileId + '.json');

  try {
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    if (fs.existsSync(metaPath)) fs.unlinkSync(metaPath);
    console.log(`[DESTROYED] File ${fileId} has been permanently deleted.`);
  } catch (err) {
    console.error(`[CLEANUP ERROR] ${fileId}:`, err.message);
  }
}

// Background cleanup: Runs every 60 seconds, sweeps for expired files
// This catches files that expired while nobody was downloading them
setInterval(() => {
  try {
    const files = fs.readdirSync(UPLOADS_DIR).filter(f => f.endsWith('.json'));
    let cleaned = 0;

    for (const file of files) {
      const metaPath = path.join(UPLOADS_DIR, file);
      const metadata = JSON.parse(fs.readFileSync(metaPath, 'utf-8'));

      if (Date.now() > metadata.expiresAt || metadata.viewsUsed >= metadata.maxViews) {
        deleteFile(metadata.id);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      console.log(`[CLEANUP] Swept ${cleaned} expired file(s).`);
    }
  } catch (err) {
    console.error('[CLEANUP ERROR]', err.message);
  }
}, 60 * 1000); // Every 60 seconds


// ═══════════════════════════════════════════════════════════════════════════════
//  SERVER INFO API
// ═══════════════════════════════════════════════════════════════════════════════

// GET /api/stats — returns server statistics
app.get('/api/stats', (_req, res) => {
  try {
    const files = fs.readdirSync(UPLOADS_DIR).filter(f => f.endsWith('.json'));
    let totalSize = 0;

    for (const file of files) {
      const filePath = path.join(UPLOADS_DIR, file.replace('.json', '.raaz'));
      if (fs.existsSync(filePath)) {
        totalSize += fs.statSync(filePath).size;
      }
    }

    res.json({
      ok: true,
      activeFiles: files.length,
      totalStorageMB: (totalSize / 1024 / 1024).toFixed(2)
    });
  } catch {
    res.json({ ok: true, activeFiles: 0, totalStorageMB: '0.00' });
  }
});


// ═══════════════════════════════════════════════════════════════════════════════
//  P2P SIGNALING SERVER (WebRTC via Socket.IO)
// ═══════════════════════════════════════════════════════════════════════════════
//
//  HOW P2P WORKS:
//  ──────────────
//  1. Sender creates a room → gets a 6-digit code
//  2. Receiver joins with the code
//  3. Server relays WebRTC signaling messages (SDP offers/answers, ICE candidates)
//  4. Once WebRTC DataChannel connects, files stream DIRECTLY between browsers
//  5. Server NEVER sees the files — only helps the two browsers find each other
//
// ═══════════════════════════════════════════════════════════════════════════════

const p2pRooms = new Map(); // roomCode → { sender: socketId, receiver: socketId }

io.on('connection', (socket) => {
  console.log(`[P2P] Client connected: ${socket.id}`);

  // ─── CREATE ROOM ─────────────────────────────────────────────────────────
  socket.on('create-room', (callback) => {
    // Generate a 6-digit room code
    let code;
    do {
      code = Math.floor(100000 + Math.random() * 900000).toString();
    } while (p2pRooms.has(code));

    p2pRooms.set(code, { sender: socket.id, receiver: null });
    socket.join(code);
    socket.p2pRoom = code;
    socket.p2pRole = 'sender';

    console.log(`[P2P] Room ${code} created by ${socket.id}`);
    callback({ ok: true, code });
  });

  // ─── JOIN ROOM ───────────────────────────────────────────────────────────
  socket.on('join-room', (code, callback) => {
    const room = p2pRooms.get(code);
    if (!room) {
      return callback({ ok: false, error: 'Room not found. Check the code.' });
    }
    if (room.receiver) {
      return callback({ ok: false, error: 'Room is full.' });
    }

    room.receiver = socket.id;
    socket.join(code);
    socket.p2pRoom = code;
    socket.p2pRole = 'receiver';

    console.log(`[P2P] ${socket.id} joined room ${code}`);
    callback({ ok: true });

    // Notify the sender that receiver has joined → sender should create WebRTC offer
    socket.to(code).emit('peer-joined');
  });

  // ─── RELAY WEBRTC SIGNALING ──────────────────────────────────────────────
  // These messages are forwarded between peers to establish the WebRTC connection
  socket.on('signal', (data) => {
    if (socket.p2pRoom) {
      socket.to(socket.p2pRoom).emit('signal', data);
    }
  });

  // ─── DISCONNECT CLEANUP ──────────────────────────────────────────────────
  socket.on('disconnect', () => {
    console.log(`[P2P] Client disconnected: ${socket.id}`);
    if (socket.p2pRoom) {
      socket.to(socket.p2pRoom).emit('peer-left');
      // If sender disconnects, destroy the room
      if (socket.p2pRole === 'sender') {
        p2pRooms.delete(socket.p2pRoom);
        console.log(`[P2P] Room ${socket.p2pRoom} destroyed (sender left)`);
      } else {
        // If receiver disconnects, allow new receiver
        const room = p2pRooms.get(socket.p2pRoom);
        if (room) room.receiver = null;
      }
    }
  });
});

// Clean up stale rooms every 5 minutes
setInterval(() => {
  const sockets = io.sockets.sockets;
  for (const [code, room] of p2pRooms) {
    const senderAlive = sockets.has(room.sender);
    if (!senderAlive) {
      p2pRooms.delete(code);
      console.log(`[P2P] Stale room ${code} cleaned up`);
    }
  }
}, 5 * 60 * 1000);


// ─── START SERVER ─────────────────────────────────────────────────────────────
// Using http server (not app.listen) so Socket.IO can share the same port
server.listen(PORT, '0.0.0.0', () => {
  const os = require('os');
  const nets = os.networkInterfaces();
  let localIP = '<your-ip>';
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal && net.address.startsWith('192.168')) {
        localIP = net.address;
      }
    }
  }
  console.log('');
  console.log('  ╔══════════════════════════════════════════════════════════╗');
  console.log('  ║                                                          ║');
  console.log(`  ║   🔐 RaazVault Server running on port ${PORT}               ║`);
  console.log('  ║                                                          ║');
  console.log(`  ║   PC:     http://localhost:${PORT}                         ║`);
  console.log(`  ║   Phone:  http://${localIP}:${PORT}                      ║`);
  console.log('  ║                                                          ║');
  console.log('  ║   ⚡ P2P Transfer + 🔗 Raaz Links — both LIVE            ║');
  console.log('  ║   The server never sees your plaintext files.            ║');
  console.log('  ║                                                          ║');
  console.log('  ╚══════════════════════════════════════════════════════════╝');
  console.log('');
});
