////////////////////////////////////////////////Pre-setting///////////////////////////////////////////////
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose")
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");

app.use(bodyParser.urlencoded({
  extended: true
}));

//use of session must be before the connection of the database
app.use(session({
  secret: "Our Secret",
  resave: false,
  saveUninitialized: false
}));

//use of passport must be after the use of session
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true,useUnifiedTopology: true});
mongoose.set("useCreateIndex",true); // to remove the error of (node:2338) DeprecationWarning: collection.ensureIndex is deprecated. Use createIndexes instead.


/////////////////////////////////////////////////////////////////////////////////////////////////////////

//create a new schema
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
})

// use of the passportLocalMongoose ***Must be set after the schema
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//create a new model (a new collection)
const User = new mongoose.model("User", userSchema);

//Simplified Passport/Passport-Local Configuration *** Must be set after the model
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});


// This part should be put at the lowest part of the setup, and right before the routes
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    console.log(profile.displayName);
    User.findOrCreate({ googleId: profile.id}, function (err, user) {
      return cb(err, user);
    });
  }
));

/////////////////////////////////////////////////////////////////////////////////////////////////////////

app.get("/", function(req, res) {
  res.render("home");
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] })); //Only access to the profile of the google user

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets page.
    res.redirect("/secrets");
});

app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});

//Secret page for the already login user
app.get("/secrets",function(req,res){
  if (req.isAuthenticated()){
    res.render("secrets");
  } else {
    res.redirect("/login")
  }
})

app.get("/logout",function(req,res){
  req.logout();
  res.redirect("/");
})

app.post("/login",function(req,res){
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user,function(err){
    if (err){
      console.log(err);
    } else {
      passport.authenticate("local")(req,res,function(){ // also send the authenticate cookie to the browser
        res.redirect("/secrets");
      })
    }
  })

});

app.post("/register", function(req, res) {
  User.register({username:req.body.username}, req.body.password, function(err,user){
    if(err){
      console.log(err);
      res.redirect("/register")
    } else {
      passport.authenticate("local")(req,res,function(){ // also send the authenticate cookie to the browser
        res.redirect("/secrets");
      })
    }
  })
});


app.listen(3000, function() {
  console.log("Server started on port 3000.");
});
