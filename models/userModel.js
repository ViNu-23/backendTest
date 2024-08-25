const mongoose = require("mongoose");
require("dotenv").config();

const deployment = `mongodb+srv://vijayvinu46:${process.env.DB_KEY}@cluster0.py4vl.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

mongoose.connect(deployment);

const userSchema = mongoose.Schema({
  avatar: {
    default: "https://res.cloudinary.com/dbejvuvsx/image/upload/v1724279320/user_avatar/jwst9a86r2clvk6ezvab.jpg",
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
  isVerified: { type: Boolean, default: false },

});

module.exports = mongoose.model("user", userSchema);
