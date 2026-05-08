require("./utils.js");
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const saltRounds = 12;

const app = express();

const Joi = require("joi");
// const mongoSanitizer = require('mongo-sanitizer').default;
//import mongoSanitizer from 'mongo-sanitizer';
const mongoSanitize = require("express-mongo-sanitize");

const PORT = process.env.PORT || 3000;

const expireTime = 1 * 60 * 60 * 1000; // expires after 1 hour (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

const { database } = include("databaseConnection");
const userCollection = database.db(mongodb_user_database).collection("users");

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// app.use(mongoSanitizer(
//     { replaceWith: '_'}
// ));

//Hack for express 5.x not setting req.query as writable
app.use((req, _res, next) => {
  Object.defineProperty(req, "query", {
    ...Object.getOwnPropertyDescriptor(req, "query"),
    value: req.query,
    writable: true,
  });

  next();
});

app.use(mongoSanitize({ replaceWith: "%" }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_session_database}`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store
    saveUninitialized: false,
    resave: true,
  }),
);

// Routes
app.get("/", (req, res) => {
  if (!req.session.authenticated) {
    res.send(`                     
          <a href="/signup">Sign up</a><br>
          <a href="/login">Login</a><br>                       
      `);
    return;
  }

  var html = `
    Hello, ${req.session.name}!<br>
     <a href="/members">Go to Members Area</a><br>
     <a href="/logout">Logout</a><br>
    `;
  res.send(html);
});

app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/login");
    return;
  }
  const images = ["luffy.png", "zoro.png", "sanji.png"];
  const randomImage = images[Math.floor(Math.random() * images.length)];

  var html = `
  Hello, ${req.session.name}! <br>
  <img src='/${randomImage}' style='width:250px;'> <br>
  <a href="/logout">Sign out</a><br>
`;
  res.send(html);
});

app.get("/signup", (req, res) => {
  var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='name' type='text' placeholder='name'><br>
    <input name='email' type='email' placeholder='email'><br>
    <input name='password' type='password' placeholder='password'><br>
    <button>Submit</button>
    </form>
    `;
  res.send(html);
});

app.post("/submitUser", async (req, res) => {
  var name = req.body.name;
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.object({
    name: Joi.string().alphanum().max(20).required(),
    email: Joi.string().email().max(50).required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ name, email, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send(
      `${validationResult.error.details[0].context.label} is required <br> <a href="/signup">Try again</a>`,
    );
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({
    name: name,
    email: email,
    password: hashedPassword,
  });
  console.log("Inserted user");

  req.session.authenticated = true;
  req.session.name = name;
  req.session.cookie.maxAge = expireTime;

  res.redirect("/members");
});

app.get("/login", (req, res) => {
  var html = `
    log in
    <form action='/loginSubmit' method='post'>    
    <input name='email' type='email' placeholder='email'><br>
    <input name='password' type='password' placeholder='password'><br>
    <button>Submit</button>
    </form>
    `;
  res.send(html);
});

app.post("/loginSubmit", async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.string().max(50).required();
  const validationResult = schema.validate(email);

  if (validationResult.error != null) {
    console.log(validationResult.error);
    var html = `
    Invalid email/password combination. <br>
    <a href="/login">Try again</a><br>
    `;
    res.send(html);
    return;
  }

  const result = await userCollection
    .find({ email: email })
    .project({ name: 1, email: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);
  if (result.length != 1) {
    console.log("user not found");
    var html = `
    Invalid email/password combination. <br>
    <a href="/login">Try again</a><br>
    `;
    res.send(html);
    return;
  }
  if (await bcrypt.compare(password, result[0].password)) {
    console.log("correct password");
    req.session.authenticated = true;
    req.session.name = result[0].name;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/");
    return;
  } else {
    console.log("incorrect password");
    var html = `
    Invalid email/password combination. <br>
    <a href="/login">Try again</a><br>
    `;
    res.send(html);
    return;
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.use(express.static(__dirname + "/public"));

app.use((req, res) => {
  res.status(404);
  res.send("Page not found - 404");
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
