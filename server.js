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
import authRoutes from "./routes/authRoutes.js";

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());
// Auth routes
app.use("/api", authRoutes);

mongoose
  .connect(process.env.MONGO_URI || "mongodb://127.0.0.1:27017/e2e-chat")
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB Error", err));

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "http://localhost:3000", methods: ["GET", "POST"] },
});

const JWT_SECRET = process.env.JWT_SECRET || "change_me_secret";

// --- AUTH ROUTES ---
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ error: "All fields required" });

    const exists = await User.findOne({ $or: [{ username }, { email }] });
    if (exists) return res.status(400).json({ error: "User exists" });

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ username, email, password: hash });
    const token = jwt.sign({ id: user._id, username }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ user, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(400).json({ error: "Invalid credentials" });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ error: "Invalid credentials" });
  const token = jwt.sign({ id: user._id, username }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ user, token });
});

// --- SOCKET.IO CHAT ---
const connectedUsers = new Map();

io.on("connection", (socket) => {
  console.log("🔌 New client connected");

  socket.on("join", (username) => {
    socket.username = username;
    connectedUsers.set(socket.id, username);
    socket.join("general");
    io.emit("userList", Array.from(connectedUsers.values()));
  });

  socket.on("message", async (data) => {
    const msg = await Message.create(data);
    io.to(data.room || "general").emit("message", data);
  });

  socket.on("typing", (room) => {
    socket.to(room).emit("typing", socket.username);
  });

  socket.on("stopTyping", (room) => {
    socket.to(room).emit("stopTyping", socket.username);
  });

  socket.on("disconnect", () => {
    connectedUsers.delete(socket.id);
    io.emit("userList", Array.from(connectedUsers.values()));
    console.log("❌ Client disconnected");
  });
});

server.listen(5000, () =>
  console.log("🚀 Server running on http://localhost:5000")
);