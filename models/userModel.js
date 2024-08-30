const mongoose = require("mongoose");
require("dotenv").config();

const deployment = `mongodb+srv://vijayvinu46:${process.env.DB_KEY}@cluster0.py4vl.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

mongoose.connect(deployment)
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('Error connecting to MongoDB:'));

const userSchema = mongoose.Schema({
  avatar: {
    default: "https://res.cloudinary.com/dbejvuvsx/image/upload/v1724517310/user_avatar/czlgmooz32partrzfyxa.jpg",
    type: String,
  },
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  location: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  posts: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "post",
    },
  ],
  otp: {
    type: String,
  },
  isVerified: { type: Boolean, default: false },

});

module.exports = mongoose.model("user", userSchema);
