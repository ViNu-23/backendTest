const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const multer = require("multer");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const cloudinary = require("cloudinary").v2;
const nodemailer = require("nodemailer");
const otpGenerator = require("otp-generator");
const cors = require("cors");

const userModel = require("./models/userModel");
const postModel = require("./models/postModel");

const bcryptSalt = bcrypt.genSaltSync(parseInt(process.env.SALT));
const jwtKey = process.env.JWT_KEY;

app.use(express.json());
app.use(cookieParser());

const corsOptions = {
  origin: ["https://blog-frontend-vijay.vercel.app", "http://localhost:5173"],
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
  credentials: true,
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).send("Unauthorized: No token provided");
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, jwtKey, (err, tokenData) => {
    if (err) {
      return res.status(403).send("Unauthorized: Invalid token");
    }

    req.user = tokenData; // Attach token data to req object
    next(); // Proceed to the next middleware or route handler
  });
};

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

app.get("/", (req, res) => {
  res.send("basic test");
});

app.post("/signup", async (req, res) => {
  const { name, email, location, password } = req.body;

  try {
    let tryEmail = await userModel.findOne({ email });
    if (tryEmail) {
      return res.status(409).json({ message: "Email already in use" });
    }

    const otp = otpGenerator.generate(6, {
      digits: true,
      lowerCaseAlphabets: false,
      upperCaseAlphabets: false,
      specialChars: false,
    });

    const newUser = new userModel({
      name,
      email,
      location,
      password: bcrypt.hashSync(password, bcryptSalt),
      otp,
    });

    await newUser.save();

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Verify Your Email - OTP Code Inside",
      text: `Dear ${name},\n\nThank you for signing up! To complete your registration, please use the following One-Time Password (OTP) to verify your email address:\n\n🔑 Your OTP Code: ${otp}\n\nPlease enter this code in the verification form.\n\nIf you did not initiate this request, please ignore this email.`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        return res.status(500).json({ message: "Failed to send OTP email" });
      }
      return res.status(201).json({
        message:
          "Signup initiated! Please verify your email with the OTP sent.",
      });
    });
  } catch (error) {
    console.error("Signup Error:", error);
    return res.status(500).json({ message: "Internal Server Error" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const existUser = await userModel.findOne({ email });

    if (!existUser) {
      return res.status(404).send("Email not found");
    }

    const comparePassword = bcrypt.compareSync(password, existUser.password);
    if (comparePassword) {
      jwt.sign(
        { id: existUser.id, email: existUser.email },
        jwtKey,
        { expiresIn: "7d" }, // Token valid for 7 days
        (err, token) => {
          if (err) throw err;
          res.status(200).json({ token, user: existUser });
        }
      );
    } else {
      return res.status(404).send("Incorrect password");
    }
  } catch (error) {
    return res.status(500).send(error.message);
  }
});

app.post("/verifyotp", async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await userModel.findOne({ email });

    if (!user) {
      return res.status(400).send("No user found");
    }

    if (user.otp !== otp) {
      return res.status(400).send("Invalid OTP");
    }

    user.isVerified = true;
    user.otp = undefined;
    await user.save();

    jwt.sign(
      { id: user.id, email: user.email },
      jwtKey,
      { expiresIn: "7d" },
      (err, token) => {
        if (err) throw err;
        res.status(200).json({ token, user: user });
      }
    );
  } catch (error) {
    res.status(500).send("Internal Server Error");
  }
});

app.post("/forgotpassword", async (req, res) => {
  const { email } = req.body;

  const user = await userModel.findOne({ email });
  if (!user) {
    return res
      .status(404)
      .json({ message: "Email not registered. Create new Account" });
  }

  try {
    const otp = otpGenerator.generate(6, {
      digits: true,
      lowerCaseAlphabets: false,
      upperCaseAlphabets: false,
      specialChars: false,
    });

    user.otp = otp;
    await user.save();

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Reset Your Password - OTP Code Inside",
      text: `Dear ${user.name},\n\nYou have requested to reset your password. Please use the following One-Time Password (OTP) to proceed:\n\n🔑 Your OTP Code: ${otp}\n\nPlease enter this code within the next 10 minutes.\n\nIf you did not request this, please ignore this email.`,
    };

    transporter.sendMail(mailOptions, (error) => {
      if (error) {
        console.error("Error sending email:", error);
        return res.status(500).json({ message: "Failed to send OTP email" });
      }

      res.status(200).json({
        message: `OTP sent to your ${email}. Please verify to reset your password.`,
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.post("/setnewpassword", verifyToken, async (req, res) => {
  const userEmail = req.user.email;
  const { newpassword } = req.body;

  try {
    const user = await userModel.findOne({ email: userEmail });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    user.password = await bcrypt.hash(newpassword, bcryptSalt);
    await user.save();

    res.status(200).json({ message: "Password reset successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

//todo left for feature updates
// app.get("/edituser", async (req, res) => {
//   const { token } = req.cookies;
//   if (token) {
//     jwt.verify(token, jwtKey, {}, async (err, tokenData) => {
//       if (err) {
//         res
//           .status(500)
//           .json({ success: false, message: "Token verification failed" });
//       } else {
//         try {
//           const editedUser = await userModel.findById(tokenData.id);

//           res.status(200).json(editedUser);
//         } catch (error) {
//           res.status(500).send({ success: false, message: error.message });
//         }
//       }
//     });
//   } else {
//     res.status(404).send("session expired login again");
//   }
// });

//todo left for feature updates
// app.post("/edituser", async (req, res) => {
//   const { token } = req.cookies;
//   const { name, email, location, password } = req.body;

//   if (token) {
//     jwt.verify(token, jwtKey, {}, async (err, tokenData) => {
//       if (err) {
//         res
//           .status(500)
//           .json({ success: false, message: "Token verification failed" });
//       } else {
//         try {
//           const editedUser = await userModel.findById(tokenData.id);
//           editedUser.set({
//             name,
//             email,
//             location,
//             password: bcrypt.hashSync(password, bcryptSalt),
//           });
//           editedUser.save();

//           res.status(200).json({
//             success: true,
//             message: "user updated",
//           });
//         } catch (error) {
//           res.status(500).send({ success: false, message: error.message });
//         }
//       }
//     });
//   } else {
//     res.status(404).send("session expired login again");
//   }
// });

app.post(
  "/setavatar",
  verifyToken,
  upload.single("avatar"),
  async (req, res) => {
    const userId = req.user.id;
    try {
      const file = req.file;
      if (!file) {
        return res
          .status(400)
          .json({ success: false, message: "No file uploaded" });
      }
      const user = await userModel.findById(userId);
      if (user.avatar) {
        const publicId = user.avatar.split("/").pop().split(".")[0];
        await cloudinary.uploader.destroy(`user_avatar/${publicId}`);
      }
      cloudinary.uploader
        .upload_stream({ folder: "user_avatar" }, async (error, result) => {
          if (error) {
            return res
              .status(500)
              .send("Upload to Cloudinary failed", error.message);
          }

          user.set({ avatar: result.secure_url });
          await user.save();
          res.status(200).json(result.secure_url);
        })
        .end(file.buffer); // Ensure file.buffer is available here
    } catch (error) {
      console.error(error);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
);

app.get("/posts", async (req, res) => {
  const posts = await postModel.find().populate("owner");
  res.status(200).json(posts);
});

app.get("/readpost/:id", async (req, res) => {
  const { id } = req.params;
  res.send(await postModel.findById(id).populate("owner"));
});

app.post("/postimage", upload.single("post"), (req, res) => {
  const file = req.file;
  try {
    cloudinary.uploader
      .upload_stream({ folder: "post_images" }, async (error, result) => {
        if (error) {
          return res.status(500).json({ message: "Upload to Cloudinary failed", error });
        } else {
          res.status(200).json(result.secure_url);
        }
      })
      .end(file.buffer); 
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

app.post("/deletepostimage", async (req, res) => {
  const { imagename } = req.body;

  if (!imagename) {
    return res.status(400).json({ message: "Image URL is required" });
  }

  try {
    const parts = imagename.split("/");
    const publicIdWithExtension = parts[parts.length - 1];
    const publicId = publicIdWithExtension.split(".")[0];

    const result = await cloudinary.uploader.destroy(`post_images/${publicId}`);

    if (result.result !== "ok") {
      return res.status(500).json({ message: "Failed to delete image" });
    }

    res.status(200).json({ message: "Image deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

app.post("/createpost", verifyToken, async (req, res) => {
  const userId = req.user.id;
  const { title, image, description, category } = req.body;

  try {
    const newPost = await postModel.create({
      title,
      image,
      category,
      description,
      date: new Date(),
      owner: userId,
    });
    await userModel.findByIdAndUpdate(userId, {
      $push: { posts: newPost._id },
    });
    res.status(200).send("Post created successfully");
  } catch (error) {
    res.status(404).send(error.message);
  }
});

app.get("/editpost/:id", async (req, res) => {
  const { id } = req.params;
  res.json(await postModel.findById(id));
});

app.post("/editpost/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  const { title, image, description, category } = req.body;

  try {
    let editPost = await postModel.findById(id);
    editPost.set({
      title,
      image,
      description,
      category,
    });
    await editPost.save();
    res.status(200).send("post updated");
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.get("/userpost", verifyToken, async (req, res) => {
  const userId = req.user.id;
  try {
    const post = await postModel.find({ owner: userId });
    res.status(200).json(post);
  } catch (error) {
    req.status(404).send(error.message);
  }
});

app.post("/deletepost", verifyToken, async (req, res) => {
  const { id } = req.body;
  const userId = req.user.id;

  try {
    const postToDelete = await postModel.findById(id);

    if (!postToDelete) {
      return res.status(404).send("Post not found");
    }

    if (postToDelete.owner.toString() !== userId) {
      return res
        .status(403)
        .send("Forbidden: You are not the owner of this post");
    }

    const parts = postToDelete.image.split("/");
    const publicIdWithExtension = parts[parts.length - 1];
    const publicId = publicIdWithExtension.split(".")[0];

    const result = await cloudinary.uploader.destroy(`post_images/${publicId}`);

    if (result.result !== "ok") {
      return res.status(500).json({ message: "Failed to delete image" });
    }

    await postModel.findByIdAndDelete(id);
    await userModel.findByIdAndUpdate(userId, { $pull: { posts: id } });

    res.status(200).send("Post deleted successfully");
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.post("/like", verifyToken, async (req, res) => {
  const { postId } = req.body;
  const userEmail = req.user.email; 

  try {
    const post = await postModel.findById(postId);

    if (!post) {
      return res
        .status(404)
        .json({ success: false, message: "Post not found" });
    }

    if (!post.lovedBy.includes(userEmail)) {
      post.lovedBy.push(userEmail);
      await post.save();
    }

    res.status(200).json({ success: true, message: "Post Liked" });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.post("/dislike", verifyToken, async (req, res) => {
  const { postId } = req.body;
  const userEmail = req.user.email;

  try {
    const post = await postModel.findById(postId);

    if (!post) {
      return res
        .status(404)
        .json({ success: false, message: "Post not found" });
    }
    if (post.lovedBy.includes(userEmail)) {
      post.lovedBy = post.lovedBy.filter((email) => email !== userEmail);
      await post.save();
    }

    res.status(200).json({ success: true, message: "Post Disliked" });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.get("/publicprofile/:email", async (req, res) => {
  const { email } = req.params;

  try {
    const user = await userModel.findOne({ email: email }).populate("posts");

    if (user) {
      res.status(200).json(user);
    } else {
      res.status(404).json({message:"User not found"});
    }
  } catch (error) {
    res.status(404).send("Failed to find user");
  }
});

app.get("/userlikedposts", verifyToken, async (req, res) => {
  const { email } = req.user;

  try {
    const likedPosts = await postModel.find({ lovedBy: email }).populate("owner");

    if (likedPosts.length === 0) {
      return res.status(404).json({ success: false, message: "No liked posts found" });
    }

    res.status(200).json({ success: true, posts: likedPosts });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});


app.post("/logout", (req, res) => {
  res
    .cookie("token", "", {
      httpOnly: true,
      expires: new Date(0),
    })
    .status(200)
    .send("Successfully logged out");
});

app.listen(3000, (err) => {
  if (err) {
    console.log(err);
  }
  console.log("Connected on port 3000");
});
