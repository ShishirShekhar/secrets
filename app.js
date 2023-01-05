// add environment config
require("dotenv").config();

// import required modules
const express = require("express");
const bodyParser= require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

// initialize the app
const app = express();

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

// Set up session
app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true
}));

// Set up Passport
app.use(passport.initialize());
app.use(passport.session());

// connect mongodb
mongoose.connect(process.env.URL);

// create userSchema
const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    secret: String
})

// plugin
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// create model for the schema
const User = mongoose.model("User", userSchema);

// create user strategy for passport
passport.use(User.createStrategy());

// serialize and deserialize of model for passport session support
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
        cb(null, { id: user.id, username: user.username });
    });
});
  
passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
        return cb(null, user);
    });
});


// google auth strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/secrets"
    },
    function(accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));


// get routes
// home
app.get("/", function(req, res) {
    res.render("home");
});


// secrets
app.get("/secrets", function(req, res) {
    User.find({"secret": {$ne: null}}, function(err, foundUsers) {
        if (err) {
            console.log(err);
            res.redirect("/");
        } else {
            if (foundUsers) {
                res.render("secrets", {userWithSecrets: foundUsers});
            }
        }
    });
});


// submit
app.get("/submit", function(req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/");
    }    
});


// register
app.get("/register", function(req, res) {
    res.render("register");
});


// login
app.get("/login", function(req, res) {
    res.render("login");
});


// logout
app.get("/logout", function(req, res) {
    req.logout();
    res.redirect("/");
});


// google auth
app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] }));

app.get("/auth/google/secrets", 
    passport.authenticate("google", { failureRedirect: "/login" }),
    function(req, res) {
        // Successful authentication, redirect secrets.
        res.redirect("/secrets");
    }
);


// post routes
// register
app.post("/register", function(req, res) {
    // register user
    User.register({username: req.body.username, active: false}, req.body.password, function(err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            });
        }
    });
});


// login
app.post("/login", function(req, res) {
    // create user details
    const user = new User({
        username: req.body.username,
        password: req.body.password
    })
    // login user
    req.login(user, function(err) {
        if (err) {
            console.log(err);
            res.redirect("/login");
        } else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            });
        }
    });
});


// submit
app.post("/submit", function(req, res) {
    // find user
    User.findById(req.user.id, function(err, foundList) {
        if (err) {
            console.log(err);
        } else {
            if (foundList) {
                foundList.secret = req.body.secret;
                foundList.save(function() {
                    res.redirect("/secrets");
                });
            }
        }
    })   
});


// host the app
let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}

app.listen(port, function() {
  console.log("Server has started successfully");
});
