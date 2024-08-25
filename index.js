const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const multer = require("multer");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const cloudinary = require("cloudinary").v2;

const userModel = require("./models/userModel");
const postModel = require("./models/postModel");
const bcryptSalt = bcrypt.genSaltSync(parseInt(process.env.SALT));
const jwtKey = process.env.JWT_KEY;

app.use(express.json());
app.use(cookieParser());

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

app.get("/",(req, res) => {
  res.send("basic test");
})

app.post("/signup", async (req, res) => {
  let { name, email, location, password } = req.body;
  let tryEmail = await userModel.findOne({ email });
  if (tryEmail) {
    return res.status(409).send("Email already in use");
  } else {
    try {
      const user = await userModel.create({
        name,
        email,
        location,
        password: bcrypt.hashSync(password, bcryptSalt),
      });

      jwt.sign(
        {
          name: name,
          email: email,
        },
        jwtKey,
        {},
        (err, token) => {
          if (err) throw err;
          res.cookie(token).json(user);
        }
      );
    } catch (error) {
      console.error(error);
      res.status(500).send("Internal Server Error");
    }
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
      res
        .status(200)
        .json({ message: "success", url: result.secure_url });
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

app.get("/editpost/:id", async (req, res)=>{
  const { id } = req.params;
  res.json(await postModel.findById(id));
})

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
