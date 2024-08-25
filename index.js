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
const session = require("express-session");
const cors = require('cors');

const userModel = require("./models/userModel");
const postModel = require("./models/postModel");

const bcryptSalt = bcrypt.genSaltSync(parseInt(process.env.SALT));
const jwtKey = process.env.JWT_KEY;

app.use(express.json());
app.use(cookieParser());

app.use(
  session({
    secret: process.env.SESSION_SECRET, // Set this in your .env
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }, // Set to true if using HTTPS
  })
);

const corsOptions = {
  origin: 'https://blog-frontend-vijay.vercel.app/',
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
  credentials: true, 
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

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
    // Check if the email is already in use
    let tryEmail = await userModel.findOne({ email });
    if (tryEmail) {
      return res.status(409).json({ message: "Email already in use" });
    }

    // Generate a 6-digit OTP
    const otp = otpGenerator.generate(6, {
      digits: true,
      lowerCaseAlphabets: false,
      upperCaseAlphabets: false,
      specialChars: false,
    });

    // Temporarily store user data and OTP
    const tempUser = { name, email, location, password, otp };

    // Email options
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Verify Your Email - OTP Code Inside",
      text: `Dear ${name},\n\nThank you for signing up! To complete your registration, please use the following One-Time Password (OTP) to verify your email address:\n\n🔑 Your OTP Code: ${otp}\n\nPlease enter this code in the verification form within the next 10 minutes to secure your account.\n\nIf you did not initiate this request, please ignore this email.\n\nBest regards,\nThe [Your Company] Team\n\nNeed help? Contact us at [support@yourcompany.com]`,
    };

    // Send OTP email
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        return res.status(500).json({ message: "Failed to send OTP email" });
      }
      // Store the temporary user in the session
      req.session.tempUser = tempUser;

      // Respond to the client after email is sent
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

app.post("/verifyotp", async (req, res) => {
  const { otp } = req.body;

  // Retrieve the temporarily stored user data
  const tempUser = req.session.tempUser; // Example using session

  if (!tempUser) {
    return res.status(400).send("No signup process found");
  }

  if (tempUser.otp !== otp) {
    return res.status(400).send("Invalid OTP");
  }

  try {
    // Create the user in the database after successful OTP verification
    const user = await userModel.create({
      name: tempUser.name,
      email: tempUser.email,
      location: tempUser.location,
      password: bcrypt.hashSync(tempUser.password, bcryptSalt),
      isVerified: true,
    });

    // Clear the temporary user data
    req.session.tempUser = null;
    return res
      .status(201)
      .json({ message: "Email verified and user created successfully!", user });
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});
 
app.post("/login", async (req, res) => {
  let { email, password } = req.body;
  let existUser = await userModel.findOne({ email });
  if (!existUser) {
    res.status(404).send("Email not found");
  } else {
    let comparePassword = bcrypt.compareSync(password, existUser.password);
    if (comparePassword) {
      jwt.sign(
        {
          id: existUser.id,
          email: existUser.email,
        },
        jwtKey,
        {},
        (err, token) => {
          if (err) throw err;
          res.cookie("token", token).json(existUser);
        }
      );
    } else {
      res.status(404).send("password miss match");
    }
  }
});

// app.post("/forgotpassword", async (req, res) => {
//   const { email } = req.body;

//   const user = await userModel.findOne({ email });
//   if (!user) {
//     return res.status(404).json({ message: "User email not found" });
//   }

//   try {
//     const otp = otpGenerator.generate(6, {
//       digits: true,
//       lowerCaseAlphabets: false,
//       upperCaseAlphabets: false,
//       specialChars: false,
//     });

//     // Store the OTP and email temporarily in a session or cache as a single object
//     req.session.resetPasswordData = {
//       otp,
//       email
//     };

//     // Send the OTP to the user's email
//     const mailOptions = {
//       from: process.env.EMAIL_USER,
//       to: email,
//       subject: "Reset Your Password - OTP Code Inside",
//       text: `Dear ${user.name},\n\nYou have requested to reset your password. Please use the following One-Time Password (OTP) to proceed:\n\n🔑 Your OTP Code: ${otp}\n\nPlease enter this code within the next 10 minutes.\n\nIf you did not request this, please ignore this email.\n\nBest regards,\nThe [Your Company] Team`,
//     };

//     transporter.sendMail(mailOptions, (error) => {
//       if (error) {
//         console.error("Error sending email:", error);
//         return res.status(500).json({ message: "Failed to send OTP email" });
//       }

//       res.status(200).json({ message: "OTP sent to your email. Please verify to reset your password." });
//     });
//   } catch (error) {
//     console.error(error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

// app.post("/validateotp", async (req, res) => {
//   const { otp } = req.body;

//   const resetPasswordData = req.session.resetPasswordData;

//   if (!resetPasswordData) {
//     return res.status(400).json({ message: "No reset process found" });
//   }

//   if (resetPasswordData.otp !== otp) {
//     return res.status(400).json({ message: "Invalid OTP" });
//   }

//   res.status(200).json({ message: "OTP validated successfully. You can now reset your password." });
// });

// app.post("/setnewpassword", async (req, res) => {
//   const { newPassword } = req.body;

//   const resetPasswordData = req.session.resetPasswordData;

//   if (!resetPasswordData) {
//     return res.status(400).json({ message: "No reset process found" });
//   }

//   try {
//     const hashedPassword = bcrypt.hashSync(newPassword, bcryptSalt);

//     // Update the user's password in the database
//     await userModel.updateOne({ email: resetPasswordData.email }, { password: hashedPassword });

//     // Clear the session data
//     req.session.resetPasswordData = null;

//     res.status(200).json({ message: "Password reset successfully!" });
//   } catch (error) {
//     console.error(error);
//     res.status(500).json({ message: "Internal Server Error" });
//   }
// });

app.get("/edituser", async (req, res) => {
  const { token } = req.cookies;
  if (token) {
    jwt.verify(token, jwtKey, {}, async (err, tokenData) => {
      if (err) {
        res
          .status(500)
          .json({ success: false, message: "Token verification failed" });
      } else {
        try {
          const editedUser = await userModel.findById(tokenData.id);

          res.status(200).json(editedUser);
        } catch (error) {
          res.status(500).send({ success: false, message: error.message });
        }
      }
    });
  } else {
    res.status(404).send("session expired login again");
  }
});

app.post("/edituser", async (req, res) => {
  const { token } = req.cookies;
  const { name, email, location, password } = req.body;

  if (token) {
    jwt.verify(token, jwtKey, {}, async (err, tokenData) => {
      if (err) {
        res
          .status(500)
          .json({ success: false, message: "Token verification failed" });
      } else {
        try {
          const editedUser = await userModel.findById(tokenData.id);
          editedUser.set({
            name,
            email,
            location,
            password: bcrypt.hashSync(password, bcryptSalt),
          });
          editedUser.save();

          res.status(200).json({
            success: true,
            message: "user updated",
          });
        } catch (error) {
          res.status(500).send({ success: false, message: error.message });
        }
      }
    });
  } else {
    res.status(404).send("session expired login again");
  }
});

app.post("/setavatar", upload.single("avatar"), (req, res) => {
  const file = req.file;
  const { token } = req.cookies;
  //check token exists or not
  if (token) {
    jwt.verify(token, jwtKey, {}, async (err, tokenData) => {
      if (err) {
        res
          .status(500)
          .json({ success: false, message: "Token verification failed" });
      } else {
        //find user according to the token
        const user = await userModel.findById(tokenData.id);
        //if founded user already has avatar image
        if (user.avatar) {
          //find the avatar image
          const publicId = user.avatar.split("/").pop().split(".")[0];
          //delete that image from cloudinary
          await cloudinary.uploader.destroy(`user_avatar/${publicId}`);
        }
        //after deleting existing avatar or create new avatar image
        cloudinary.uploader
          .upload_stream({ folder: "user_avatar" }, async (error, result) => {
            if (error) {
              return res
                .status(500)
                .send("Upload to Cloudinary failed", error.message);
            } else {
              user.set({
                avatar: result.secure_url,
              });
              await user.save();
              res
                .status(200)
                .json({ message: "success", url: result.secure_url });
            }
          })
          .end(file.buffer);
      }
    });
  } else {
    res.status(404).send("Session expired, login again.");
  }
});

app.get("/posts", async (req, res) => {
  const posts = await postModel.find().populate("owner");
  res.status(200).json({ posts });
});

app.get("/readpost/:id", async (req, res)=>{
const {id} = req.params;
res.send(await postModel.findById(id));  
})

app.post("/postimage", upload.single("post"), (req, res) => {
  const file = req.file;
  try {
    cloudinary.uploader
      .upload_stream({ folder: "post_images" }, async (error, result) => {
        if (error) {
          return res
            .status(500)
            .send("Upload to Cloudinary failed", error.message);
        } else {
          res.status(200).json({ message: "success", url: result.secure_url });
        }
      })
      .end(file.buffer);
  } catch (error) {
    res.status(500).send(error.message);
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

app.post("/createpost", async (req, res) => {
  const { token } = req.cookies;
  const { title, image, description } = req.body;
  if (token) {
    jwt.verify(token, jwtKey, {}, async (err, tokenData) => {
      if (err) {
        res
          .status(500)
          .json({ success: false, message: "Token verification failed" });
      } else {
        await postModel.create({
          title,
          image,
          description,
          date: new Date(),
          owner: tokenData.id,
        });

        res.status(200).send("post created");
      }
    });
  } else {
    res.status(404).send("session expired login again");
  }
});

app.get("/editpost/:id", async (req, res) => {
  const { id } = req.params;
  res.json(await postModel.findById(id));
});

app.post("/editpost/:id", async (req, res) => {
  const { id } = req.params;
  const { title, image, description } = req.body;

  try {
    let editPost = await postModel.findById(id);
    editPost.set({
      title,
      image,
      description,
    });
    await editPost.save();
    res.status(200).send("post updated");
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.post("/deletepost/:id", async (req, res) => {
  const { id } = req.params;
  try {
    await postModel.findOneAndDelete(id);
    res.status(200).send("post deleted");
  } catch (error) {
    res.send(500).send(error.message);
  }
});

app.listen(3000, (err) => {
  if (err) {
    console.log(err);
  }
  console.log("Connected on port 3000");
});
