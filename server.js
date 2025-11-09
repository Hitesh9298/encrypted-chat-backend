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

mongoose
  .connect(process.env.MONGO_URI || "mongodb://127.0.0.1:27017/e2e-chat")
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB Error", err));

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "http://localhost:3000", methods: ["GET", "POST"] },
});

const JWT_SECRET = process.env.JWT_SECRET || "change_me_secret";

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
};

// AUTH ROUTES
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password, publicKey } = req.body;
    console.log("🔐 Register request:", { username, email, hasPublicKey: !!publicKey });
    
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

app.post("/api/uploadPublicKey", verifyToken, async (req, res) => {
  try {
    console.log("🔐 Upload public key for user:", req.user.username);

    const { publicKey } = req.body;
    if (!publicKey) {
      console.log("❌ Missing public key");
      return res.status(400).json({ error: "Missing public key" });
    }

    const user = await User.findByIdAndUpdate(
      req.user.id, 
      { publicKey },
      { new: true }
    );
    
    if (!user) {
      console.log("❌ User not found:", req.user.id);
      return res.status(404).json({ error: "User not found" });
    }

    console.log("✅ Public key updated for:", user.username);
    res.json({ message: "Public key saved successfully" });
  } catch (err) {
    console.error("❌ Error uploading public key:", err);
    res.status(500).json({ error: "Server error saving public key" });
  }
});

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

// ROOM ROUTES
app.post("/api/rooms", verifyToken, async (req, res) => {
  try {
    const { name, description, members } = req.body;
    const creator = req.user.username;

    console.log("🏗️ Creating room:", { name, creator, members });

    if (!name || name.trim().length === 0) {
      return res.status(400).json({ error: "Room name is required" });
    }

    const existing = await Room.findOne({ name: name.toLowerCase() });
    if (existing) {
      return res.status(400).json({ error: "Room already exists" });
    }

    const memberList = members && Array.isArray(members) 
      ? [...new Set([creator, ...members])]
      : [creator];

    const room = await Room.create({
      name: name.toLowerCase(),
      description: description || "",
      members: memberList,
      createdBy: creator,
    });

    console.log("✅ Room created:", room.name, "with members:", memberList);
    
    io.emit("roomCreated", {
      name: room.name,
      description: room.description,
      members: room.members,
      createdBy: room.createdBy,
      memberCount: room.members.length,
    });

    memberList.forEach((member) => {
      if (member !== creator) {
        const memberSocketId = userSockets.get(member);
        if (memberSocketId) {
          io.to(memberSocketId).emit("addedToRoom", {
            roomName: room.name,
            addedBy: creator,
            description: room.description,
          });
          console.log(`✅ Notified ${member} about being added to ${room.name}`);
        }
      }
    });

    res.json({ 
      room: {
        name: room.name,
        description: room.description,
        members: room.members,
        createdBy: room.createdBy,
        memberCount: room.members.length,
      }
    });
  } catch (err) {
    console.error("❌ Error creating room:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/rooms", verifyToken, async (req, res) => {
  try {
    console.log("📋 Fetching rooms for user:", req.user.username);
    
    const rooms = await Room.find({});
    
    console.log("✅ Found rooms:", rooms.length);
    res.json({ 
      rooms: rooms.map(r => ({
        name: r.name,
        description: r.description,
        members: r.members,
        createdBy: r.createdBy,
        memberCount: r.members.length,
      }))
    });
  } catch (err) {
    console.error("❌ Error fetching rooms:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/rooms/:roomName/join", verifyToken, async (req, res) => {
  try {
    const { roomName } = req.params;
    const username = req.user.username;

    console.log("👤 User joining room:", { username, roomName });

    const room = await Room.findOne({ name: roomName.toLowerCase() });
    if (!room) {
      return res.status(404).json({ error: "Room not found" });
    }

    if (room.members.includes(username)) {
      return res.status(400).json({ error: "Already a member" });
    }

    room.members.push(username);
    await room.save();

    console.log("✅ User joined room:", { username, roomName });

    io.emit("userJoinedRoom", {
      room: roomName,
      username,
      members: room.members,
    });

    res.json({ 
      message: "Joined room successfully",
      room: {
        name: room.name,
        members: room.members,
        memberCount: room.members.length,
      }
    });
  } catch (err) {
    console.error("❌ Error joining room:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/rooms/:roomName/leave", verifyToken, async (req, res) => {
  try {
    const { roomName } = req.params;
    const username = req.user.username;

    console.log("🚪 User leaving room:", { username, roomName });

    if (roomName.toLowerCase() === "general") {
      return res.status(400).json({ error: "Cannot leave general room" });
    }

    const room = await Room.findOne({ name: roomName.toLowerCase() });
    if (!room) {
      return res.status(404).json({ error: "Room not found" });
    }

    room.members = room.members.filter(m => m !== username);
    await room.save();

    console.log("✅ User left room:", { username, roomName });

    io.emit("userLeftRoom", {
      room: roomName,
      username,
      members: room.members,
    });

    res.json({ 
      message: "Left room successfully",
    });
  } catch (err) {
    console.error("❌ Error leaving room:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.delete("/api/rooms/:roomName", verifyToken, async (req, res) => {
  try {
    const { roomName } = req.params;
    const username = req.user.username;

    console.log("🗑️ Deleting room:", { username, roomName });

    if (roomName.toLowerCase() === "general") {
      return res.status(400).json({ error: "Cannot delete general room" });
    }

    const room = await Room.findOne({ name: roomName.toLowerCase() });
    if (!room) {
      return res.status(404).json({ error: "Room not found" });
    }

    if (room.createdBy !== username) {
      return res.status(403).json({ error: "Only room creator can delete" });
    }

    await Room.deleteOne({ name: roomName.toLowerCase() });

    console.log("✅ Room deleted:", roomName);

    io.emit("roomDeleted", { room: roomName });

    res.json({ message: "Room deleted successfully" });
  } catch (err) {
    console.error("❌ Error deleting room:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// SOCKET.IO
const connectedUsers = new Map();
const userSockets = new Map();

io.on("connection", (socket) => {
  console.log("🔌 New client connected:", socket.id);

  socket.on("join", async (username) => {
    console.log("👤 User joining:", username);
    socket.username = username;
    connectedUsers.set(socket.id, username);
    userSockets.set(username, socket.id);
    
    socket.join("general");
    
    try {
      const userRooms = await Room.find({ members: username });
      userRooms.forEach(room => {
        socket.join(room.name);
        console.log(`✅ ${username} auto-joined room: ${room.name}`);
      });
    } catch (err) {
      console.error("Error loading user rooms:", err);
    }
    
    io.emit("userList", Array.from(connectedUsers.values()));
    console.log("✅ User joined:", username, "| Total users:", connectedUsers.size);
  });

  socket.on("joinRoom", async (roomName) => {
    console.log(`👤 ${socket.username} joining room:`, roomName);
    socket.join(roomName.toLowerCase());
  });

  socket.on("leaveRoom", (roomName) => {
    console.log(`🚪 ${socket.username} leaving room:`, roomName);
    socket.leave(roomName.toLowerCase());
  });

  socket.on("message", async (data) => {
    console.log("💬 Room message from", data.sender, "to room:", data.room);
    try {
      await Message.create(data);
      // Emit to everyone in the room INCLUDING the sender
      io.to(data.room || "general").emit("message", data);
    } catch (err) {
      console.error("❌ Error saving message:", err);
    }
  });

  socket.on("directMessage", async (data) => {
    const { recipient, sender, encryptedAESKey, encryptedMessage } = data;
    console.log(`📧 DM from ${sender} to ${recipient}`);
    
    try {
      await Message.create({
        sender,
        recipient,
        ciphertext: encryptedMessage.ciphertext,
        iv: encryptedMessage.iv,
        encryptedAESKey,
        timestamp: new Date(),
      });

      const recipientSocketId = userSockets.get(recipient);
      
      if (recipientSocketId) {
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
    }
  });

  // Room typing indicators
  socket.on("typing", (room) => {
    socket.to(room).emit("typing", socket.username);
  });

  socket.on("stopTyping", (room) => {
    socket.to(room).emit("stopTyping", socket.username);
  });

  // DM typing indicators (NEW)
  socket.on("typingDM", (targetUser) => {
    const targetSocketId = userSockets.get(targetUser);
    if (targetSocketId) {
      io.to(targetSocketId).emit("typingDM", socket.username);
    }
  });

  socket.on("stopTypingDM", (targetUser) => {
    const targetSocketId = userSockets.get(targetUser);
    if (targetSocketId) {
      io.to(targetSocketId).emit("stopTypingDM", socket.username);
    }
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