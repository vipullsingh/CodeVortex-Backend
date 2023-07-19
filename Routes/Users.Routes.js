const { Blacklist } = require("../Models/blacklist.model");
const { UserModel } = require("../Models/user.model");
const bcrypt = require("bcrypt");
const express = require('express');
const app = express();
app.use(express.json());
const jwt = require("jsonwebtoken");
const { verify } = require("../middleware/jwtAuth.middleware");
const UserRoute = require("express").Router();
require("dotenv").config();
const { validationResult } = require('express-validator');
const User = require('../Models/user.model');

UserRoute.post("/register", async (req, res) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: 'Signup successful' });
  } catch (error) {
    console.error('Error signing up:', error);
    res.status(500).json({ error: 'Server error' });
  }
});


UserRoute.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    // console.log(email,password)
    const isUserExist = await User.findOne({ email });
    if (!isUserExist) {
      return res.status(401).send({ msg: "invalid username or password" });
    }

    var result = bcrypt.compareSync(password, isUserExist.password);
    // console.log(result);
    if (!result) {
      return res.status(401).send({ msg: "invalid username or password" });
    }

    const Accesstoken = jwt.sign(
      { userID: isUserExist._id },
      process.env.secretKey
    );
    // console.log(Accesstoken);

    res.send({ msg: "login successfull", user: isUserExist, Accesstoken });
  } catch (error) {
    res.send({ msg: error.msg });
  }
});
UserRoute.get("/logout", async (req, res) => {
  // we wil get the accesstoken and refreshtoken in req.headers with the respective name;
  try {
    const accesstoken = req.headers.authorization;

    const blackAccess = new Blacklist({ token: accesstoken });
    await blackAccess.save();

    res.send({ msg: "logout successfull....." });
  } catch (error) {
    res.send({ msg: error.msg });
  }
});

// FOR FRONTEND
/* This code defines a GET route for "/verify" on the UserRoute router. It uses the `verify` middleware
function to authenticate the user's access token. If the token is valid, it sends a response with a
success message. If the token is invalid or missing, it will throw an error and send a response with
an error message. */
UserRoute.get("/verify", verify, async (req, res) => {
  try {
    res.send({ msg: "Success" });
  } catch (error) {
    res.send({ msg: error.msg });
  }
});

module.exports = { UserRoute };