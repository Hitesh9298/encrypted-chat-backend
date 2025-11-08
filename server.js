// server/server.js
import express from "express";
import http from "http";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
import { Server } from "socket.io";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import User from "./models/User.js";
import Room from "./models/Room.js";
import Message from "./models/Message.js";

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

// DB connect
mongoose
  .connect(process.env.MONGO_URI || "mongodb://127.0.0.1:27017/e2e-chat")
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB Error", err));

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "http://localhost:3000", methods: ["GET", "POST"] },
});

const JWT_SECRET = process.env.JWT_SECRET || "change_me_secret";

// --- AUTH & USER ROUTES ---

// Register: expects { username, email, password, publicKey }
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password, publicKey } = req.body;
    console.log("📝 Register request:", { username, email, hasPublicKey: !!publicKey });
    
    if (!username || !email || !password || !publicKey) {
      console.log("❌ Missing fields");
      return res.status(400).json({ error: "All fields required" });
    }

    const exists = await User.findOne({ $or: [{ username }, { email }] });
    if (exists) {
      console.log("❌ User already exists:", { username, email });
      return res.status(400).json({ error: "User exists" });
    }

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ username, email, password: hash, publicKey });

    console.log("✅ User created:", { id: user._id, username: user.username });

    const token = jwt.sign({ id: user._id, username }, JWT_SECRET, { expiresIn: "7d" });

    res.json({ 
      user: { username: user.username, email: user.email }, 
      token 
    });
  } catch (err) {
    console.error("❌ Registration error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Login: accepts username OR email
app.post("/api/login", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    console.log("🔐 Login request:", { username, email, hasPassword: !!password });
    
    if (!password || (!username && !email)) {
      console.log("❌ Missing credentials");
      return res.status(400).json({ error: "Missing credentials" });
    }

    const user = username 
      ? await User.findOne({ username }) 
      : await User.findOne({ email });
    
    if (!user) {
      console.log("❌ User not found:", { username, email });
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      console.log("❌ Password mismatch for user:", user.username);
      return res.status(400).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign({ id: user._id, username: user.username }, JWT_SECRET, { expiresIn: "7d" });
    console.log("✅ Login successful:", { username: user.username, email: user.email });
    
    res.json({ user: { username: user.username, email: user.email }, token });
  } catch (err) {
    console.error("❌ Login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Get public key for a username - NEW ROUTE FOR DM
app.get("/api/public-key/:username", async (req, res) => {
  try {
    console.log("🔑 Fetching public key for:", req.params.username);
    const user = await User.findOne({ username: req.params.username });
    if (!user) {
      console.log("❌ User not found:", req.params.username);
      return res.status(404).json({ error: "User not found" });
    }
    if (!user.publicKey) {
      console.log("⚠️ User has no public key:", req.params.username);
      return res.status(404).json({ error: "Public key not found" });
    }
    console.log("✅ Public key found for:", user.username);
    res.json({ publicKey: user.publicKey });
  } catch (err) {
    console.error("❌ Error fetching public key:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Upload public key to server
app.post("/api/uploadPublicKey", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      console.log("❌ Missing authorization token");
      return res.status(401).json({ error: "Unauthorized" });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    console.log("🔐 Upload public key for user:", decoded.username);

    const { publicKey } = req.body;
    if (!publicKey) {
      console.log("❌ Missing public key");
      return res.status(400).json({ error: "Missing public key" });
    }

    const user = await User.findByIdAndUpdate(
      decoded.id, 
      { publicKey },
      { new: true }
    );
    
    if (!user) {
      console.log("❌ User not found:", decoded.id);
      return res.status(404).json({ error: "User not found" });
    }

    console.log("✅ Public key updated for:", user.username);
    res.json({ message: "Public key saved successfully" });
  } catch (err) {
    console.error("❌ Error uploading public key:", err);
    res.status(500).json({ error: "Server error saving public key" });
  }
});

// Get user list
app.get("/api/users", async (req, res) => {
  try {
    console.log("📋 Fetching user list...");
    const users = await User.find({}, { username: 1, _id: 0 });
    console.log("✅ User list:", users.length, "users");
    res.json({ users: users.map(u => u.username) });
  } catch (err) {
    console.error("❌ Error fetching user list:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// --- Socket.IO Chat with DM Support ---
const connectedUsers = new Map(); // Map<socketId, username>
const userSockets = new Map();    // Map<username, socketId> for DM routing

io.on("connection", (socket) => {
  console.log("🔌 New client connected:", socket.id);

  socket.on("join", (username) => {
    console.log("👤 User joining:", username);
    socket.username = username;
    connectedUsers.set(socket.id, username);
    userSockets.set(username, socket.id);
    socket.join("general");
    io.emit("userList", Array.from(connectedUsers.values()));
    console.log("✅ User joined:", username, "| Total users:", connectedUsers.size);
  });

  // Room message (existing - unchanged)
  socket.on("message", async (data) => {
    console.log("💬 Room message from", data.sender);
    try {
      await Message.create(data);
      io.to(data.room || "general").emit("message", data);
    } catch (err) {
      console.error("❌ Error saving message:", err);
    }
  });

  // NEW: Direct message handler
 // Replace your entire "directMessage" socket handler with this:

socket.on("directMessage", async (data) => {
  const { recipient, sender, encryptedAESKey, encryptedMessage } = data;
  console.log(`📧 DM from ${sender} to ${recipient}`);
  console.log(`📧 Encrypted data:`, { 
    hasAESKey: !!encryptedAESKey, 
    hasMessage: !!encryptedMessage,
    messageKeys: encryptedMessage ? Object.keys(encryptedMessage) : []
  });
  
  try {
    // Save to database
    await Message.create({
      sender,
      recipient,
      ciphertext: encryptedMessage.ciphertext,
      iv: encryptedMessage.iv,
      encryptedAESKey,
      timestamp: new Date(),
    });

    // Get recipient's socket ID
    const recipientSocketId = userSockets.get(recipient);
    
    console.log(`🔍 Looking for recipient ${recipient}, found socket:`, recipientSocketId);
    console.log(`🔍 Current userSockets map:`, Array.from(userSockets.entries()));
    
    if (recipientSocketId) {
      // Send to recipient - they need to decrypt it
      io.to(recipientSocketId).emit("directMessage", {
        sender,
        encryptedAESKey,
        encryptedMessage,
      });
      console.log(`✅ DM delivered to ${recipient} on socket ${recipientSocketId}`);
    } else {
      console.log(`⚠️ ${recipient} is offline - message saved to DB only`);
    }
  } catch (err) {
    console.error("❌ Error handling DM:", err);
    console.error("❌ Error stack:", err.stack);
  }
});

  socket.on("typing", (room) => {
    socket.to(room).emit("typing", socket.username);
  });

  socket.on("stopTyping", (room) => {
    socket.to(room).emit("stopTyping", socket.username);
  });

  socket.on("disconnect", () => {
    const username = connectedUsers.get(socket.id);
    console.log(`❌ Client disconnected: ${username || socket.id}`);
    
    if (username) {
      connectedUsers.delete(socket.id);
      userSockets.delete(username);
      io.emit("userList", Array.from(connectedUsers.values()));
      console.log("Remaining users:", connectedUsers.size);
    }
  });
});

server.listen(process.env.PORT || 5000, () =>
  console.log("🚀 Server running on http://localhost:5000")
);