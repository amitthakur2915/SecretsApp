const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
require('dotenv').config(); 
const encrypt = require('mongoose-encryption');

const app = express();
const PORT = process.env.PORT || 8000;
const mongoURL = process.env.MONGO_URI;

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

mongoose.connect(mongoURL)
  .then(() => console.log("MongoDB connected successfully!"))
  .catch((err) => console.error("MongoDB connection error:", err));

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

const secretKey = "thisislittlesecret.";
userSchema.plugin(encrypt, {
  secret: secretKey,
  encryptedFields: ["password"]
});

const User = mongoose.model("User", userSchema);

const secretSchema = new mongoose.Schema({
  content: String,
  userId: String
});
const Secret = mongoose.model("Secret", secretSchema);

let currentUserId = null;

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

app.get("/register", (req, res) => {
  res.render("register", { error: null });
});

app.get("/submit", async (req, res) => {
  if (!currentUserId) return res.redirect("/login");
  const secrets = await Secret.find({ userId: currentUserId });
  res.render("submit", { secrets });
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const passRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{6,}$/;

  if (!emailRegex.test(username)) {
    return res.render("register", { error: "Enter a valid email address." });
  }
  if (!passRegex.test(password)) {
    return res.render("register", {
      error: "Password must be at least 6 characters and include uppercase, lowercase, number, and special character."
    });
  }

  try {
    const existingUser = await User.findOne({ email: username });
    if (existingUser) {
      return res.render("register", { error: "User already exists." });
    }
    const newUser = new User({ email: username, password });
    const savedUser = await newUser.save();
    currentUserId = savedUser._id;
    res.redirect("/submit");
  } catch (err) {
    console.error(err);
    res.status(500).send("Registration failed.");
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const foundUser = await User.findOne({ email: username });
    if (!foundUser) {
      return res.render("login", { error: "No user found with this email." });
    }
    if (foundUser.password !== password) {
      return res.render("login", { error: "Password does not match." });
    }
    currentUserId = foundUser._id;
    res.redirect("/submit");
  } catch (err) {
    console.error(err);
    res.status(500).send("Login failed.");
  }
});

app.post("/submit", async (req, res) => {
  if (!currentUserId) return res.redirect("/login");
  const secretText = req.body.secret;
  if (secretText.trim()) {
    await new Secret({ content: secretText, userId: currentUserId }).save();
  }
  res.redirect("/submit");
});

app.get("/edit/:id", async (req, res) => {
  if (!currentUserId) return res.redirect("/login");
  const secret = await Secret.findOne({ _id: req.params.id, userId: currentUserId });
  if (!secret) return res.redirect("/submit");
  res.render("edit", { secret });
});

app.post("/edit/:id", async (req, res) => {
  if (!currentUserId) return res.redirect("/login");
  await Secret.updateOne(
    { _id: req.params.id, userId: currentUserId },
    { content: req.body.secret }
  );
  res.redirect("/submit");
});

app.post("/delete/:id", async (req, res) => {
  if (!currentUserId) return res.redirect("/login");
  await Secret.deleteOne({ _id: req.params.id, userId: currentUserId });
  res.redirect("/submit");
});

app.get("/logout", (req, res) => {
  currentUserId = null;
  res.redirect("/");
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
