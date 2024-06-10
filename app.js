const express = require("express");
const bodyParser = require("body-parser");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const env = require("dotenv");
const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");
env.config(); //configuring the environment variables

mongoose.connect("mongodb://127.0.0.1:27017/resetpasswordDB");

const usersSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  resetPasswordToken: String,
  resetPasswordExpires: Date,
});

const usersModel = new mongoose.model("Users", usersSchema);

// Configure nodemailer
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "samuelcscience@gmail.com",
    pass: process.env.TRANSPORTER_OBJ_PASSWORD,
  },
});

//BASIC ROUTES
app.get("/", function (req, res) {
  res.render("landingpg");
});
app.get("/register", function (req, res) {
  res.render("register");
});
app.post("/register", async function (req, res) {
  // NB: To ensure 0 chances of generating duplicate userid even when the database grows big, use mongoDB-generated object id(ie _id)
  const username = req.body.username;
  const email = req.body.email;
  const password = req.body.password;
  const confirmPassword = req.body.confirmPassword;
  if (password !== confirmPassword) {
    return res
      .status(400)
      .send(
        "Pasword did not match! <button><a href='/register'>Try again</a></button>"
      );
  }
  let userExist = await usersModel.findOne({ username: username });
  if (userExist) {
    res.json("userexist");
  } else {
    const newUser = new usersModel({
      username: username,
      email: email,
      password: bcrypt.hashSync(password, 10), //NB: use "hashSync()" instead of "hash()" if you don't want to include the cb;
    });
    newUser
      .save()
      .then(() => {
        res.render("login");
        // res.json("success");
      })
      .catch((err) => {
        res.json(err);
      });
  }
});
app.get("/login", function (req, res) {
  res.render("login");
});
app.post("/login", async function (req, res) {
  const email = req.body.email;
  const password = req.body.password;
  const userdata = await usersModel.find({ email: email }); //Gives back an array of objects with all emails that matched the querry.
  if (userdata.length == 1) {
    //checks to be sure that only one account exist with that email;
    if (await bcrypt.compare(password, userdata[0].password)) {
      //we are checking password for index[0] because we are sure that our array's length is 1.
      res.redirect("/home");
    } else {
      res.send("password doesn't match.");
    }
  } else {
    res.send(
      "<h2>No user account is associated with that email. Kindly consider signing up</h2>"
    );
  }
});
app.get("/home", function (req, res) {
  res.render("home");
});

//REQUEST PASSWORD RESET route
app.get("/resetPassword", function (req, res) {
  res.render("resetPasswordForm.ejs");
});

app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  const user = await usersModel.findOne({ email });

  if (!user) {
    return res.status(400).send("User not found");
  }

  // Generate a token
  const token = crypto.randomBytes(20).toString("hex");
  const expiry = Date.now() + 3600000; // 1 hour from now

  // Save token and expiry in user record
  user.resetPasswordToken = token;
  user.resetPasswordExpires = expiry;
  await user.save();

  const mailOptions = {
    to: email,
    from: "samuelcscience@gmail.com",
    subject: "Password Reset",
    text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
    Please click on the following link, or paste this into your browser to complete the process:\n\n
    http://localhost:3000/reset/${token}\n\n
    If you did not request this, please ignore this email and your password will remain unchanged.\n`,
  };

  transporter.sendMail(mailOptions, (err) => {
    if (err) {
      return res.status(500).send("Error sending email");
    }
    res.status(200).send("Email sent <button><a href='/login'>Ok</a></button>");
  });
});

//PASSWORD RESET FORM route
app.get("/reset/:token", async (req, res) => {
  const { token } = req.params;
  const user = await usersModel.findOne({
    resetPasswordToken: token,
    resetPasswordExpires: { $gt: Date.now() },
  });

  if (!user) {
    return res
      .status(400)
      .send("Password reset token is invalid or has expired.");
  }

  // Render reset password form (replace with your template engine or front-end framework)
  res.send(`
    <form action="/reset/${token}" method="POST">
      <input type="password" name="password" placeholder="New Password" required />
      <input type="password" name="confirmPassword" placeholder="Confirm New Password" required />
      <button type="submit">Reset Password</button>
    </form>
  `);
});

//HANDLE PASSWORD RESET SUBMISSION
app.post("/reset/:token", async (req, res) => {
  const { token } = req.params;
  const { password, confirmPassword } = req.body;

  if (password !== confirmPassword) {
    return res.status(400).send(
      `Passwords do not match. Try again.   <form action="/reset/${token}" method="POST">
      <input type="password" name="password" placeholder="New Password" required />
      <input type="password" name="confirmPassword" placeholder="Confirm New Password" required />
      <button type="submit">Reset Password</button>
    </form>`
    );
  }

  const user = await usersModel.findOne({
    resetPasswordToken: token,
    resetPasswordExpires: { $gt: Date.now() },
  });

  if (!user) {
    return res
      .status(400)
      .send("Password reset token is invalid or has expired.");
  }

  // Hash the new password and save it
  const hashedPassword = await bcrypt.hash(password, 10);
  user.password = hashedPassword;
  user.resetPasswordToken = undefined;
  user.resetPasswordExpires = undefined;
  await user.save();

  // Optionally send a confirmation email
  res
    .status(200)
    .send(
      "Password has been reset.  \n \n<button><a href='/login'>Login</a></button>"
    );
});

//START THE SERVER
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
