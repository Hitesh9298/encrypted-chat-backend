import mongoose from "mongoose";
const roomSchema = new mongoose.Schema({
  name: { type: String, unique: true, required: true },
  description: String,
  members: [String],
});
export default mongoose.model("Room", roomSchema);