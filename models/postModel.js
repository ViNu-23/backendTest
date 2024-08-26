const mongoose = require("mongoose");

const postSchema = mongoose.Schema({
  title: String,
  category: String,
  image: String,
  description: String,
  date: {
    type: Date,
    default: new Date(),
  },
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "user",
  },
});

module.exports = mongoose.model("post", postSchema);
