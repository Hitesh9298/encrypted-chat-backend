// server/models/Room.js
import mongoose from "mongoose";

const roomSchema = new mongoose.Schema({
  name: { 
    type: String, 
    unique: true, 
    required: true,
    lowercase: true,
    trim: true,
  },
  description: { 
    type: String, 
    default: "" 
  },
  members: [{ 
    type: String,
    required: true 
  }],
  createdBy: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

export default mongoose.model("Room", roomSchema);