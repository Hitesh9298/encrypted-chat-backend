import mongoose from "mongoose";
const messageSchema = new mongoose.Schema({
  room: { type: String, default: "general" },
  sender: String,
  ciphertext: [Number],
  iv: [Number],
  timestamp: { type: Date, default: Date.now },
});
export default mongoose.model("Message", messageSchema);