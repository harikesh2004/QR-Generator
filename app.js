const express = require("express");
const bodyParser = require("body-parser");
const admin = require("firebase-admin");
const path = require("path");
const bcrypt = require("bcrypt");
const session = require("express-session");

const app = express();

const serviceAct = require("./key.json");
admin.initializeApp({
  credential: admin.credential.cert(serviceAct),
});

const db = admin.firestore();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: "your_secret_key",
    resave: false,
    saveUninitialized: false,
  })
);

const saltRounds = 10;

app.get("/", (req, res) => {
  if (req.session.username) {
    res.render("landing", { username: req.session.username });
  } else {
    res.render("landing", { username: null });
  }
});

app.get("/signup", (req, res) => {
  res.render("signup");
});

app.post("/signup", async (req, res) => {
  const { username, email, phone, password, confirm_password } = req.body;

  if (password !== confirm_password) {
    return res.status(400).render("passmismatch");
  }

  if (!/^\d{10}$/.test(phone)) {
    return res.status(400).render("invalid-phone");
  }

  try {
    const exist = await db
      .collection("users")
      .where("email", "==", email)
      .get();
    if (!exist.empty) {
      return res.status(400).render("mexists");
    }

    const hashedPwd = await bcrypt.hash(password, saltRounds);

    await db.collection("users").add({
      username,
      email,
      phone,
      password: hashedPwd,
    });

    req.session.username = username; // Log in the user automatically
    res.redirect("/");
  } catch (err) {
    res.status(500).send("Error: " + err.message);
  }
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const exist = await db
      .collection("users")
      .where("email", "==", email)
      .get();
    if (exist.empty) {
      return res.status(401).render("logfail");
    }
    const user = exist.docs[0].data();
    const pwdMatch = await bcrypt.compare(password, user.password);
    if (pwdMatch) {
      req.session.username = user.username;
      res.redirect("/");
    } else {
      res.status(401).render("logfail");
    }
  } catch (err) {
    res.status(500).send("Error: " + err.message);
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send("Error: " + err.message);
    }
    res.redirect("/");
  });
});

app.get("/generate-qr", (req, res) => {
  if (!req.session.username) {
    res.redirect(
      "/signup?message=Please sign up or log in to access QR code generation."
    );
  } else {
    res.render("dashboard", { username: req.session.username });
  }
});

app.post("/dashboard", (req, res) => {
  const { word, username } = req.body;
  const qrCodeUrl = `https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=${encodeURIComponent(
    word
  )}`;
  res.render("dashboard", { username, word, qrCodeUrl });
});

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
