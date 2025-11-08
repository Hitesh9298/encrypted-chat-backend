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

    // Return user data and token - publicKey is already saved in DB
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

    // Find user by username OR email
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

// Get public key for a username
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

// Upload public key to server (used if user logs in without keys)
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

// Get user list (for demo)
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

// --- Socket.IO Chat ---
const connectedUsers = new Map();

io.on("connection", (socket) => {
  console.log("🔌 New client connected:", socket.id);

  socket.on("join", (username) => {
    console.log("👤 User joining:", username);
    socket.username = username;
    connectedUsers.set(socket.id, username);
    socket.join("general");
    io.emit("userList", Array.from(connectedUsers.values()));
    console.log("✅ User joined:", username, "| Total users:", connectedUsers.size);
  });

  socket.on("message", async (data) => {
    console.log("💬 Message from", data.sender, "->", data.recipient || "all");
    try {
      const msg = await Message.create(data);
      if (data.recipient) {
        io.emit("message", data);
      } else {
        io.to(data.room || "general").emit("message", data);
      }
    } catch (err) {
      console.error("❌ Error saving message:", err);
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
    connectedUsers.delete(socket.id);
    io.emit("userList", Array.from(connectedUsers.values()));
    console.log("❌ Client disconnected:", username || socket.id, "| Remaining:", connectedUsers.size);
  });
});

server.listen(process.env.PORT || 5000, () =>
  console.log("🚀 Server running on http://localhost:5000")
);