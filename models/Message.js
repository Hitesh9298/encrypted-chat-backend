// server/models/Message.js
import mongoose from "mongoose";

const messageSchema = new mongoose.Schema({
  room: { type: String, default: "general" },
  sender: String,
  recipient: String, // optional; for demo we support direct recipient
  ciphertext: [Number],
  iv: [Number],
  encryptedAESKey: [Number], // AES key encrypted with recipient public key
  timestamp: { type: Date, default: Date.now }
});

export default mongoose.model("Message", messageSchema);
