require('dotenv').config()
const express = require("express");
const bodyparser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passportLocalMongoose = require("passport-local-mongoose");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const FacebookStrategy = require("passport-facebook").Strategy;


const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyparser.urlencoded({extended: true}));

app.use(session({
    secret: "Mylittlesecret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());


//MongogDB connect
mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set("useCreateIndex", true);

//Create schema
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//Create model
const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

//Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },
    function(accessToken, refreshToken, profile, cb) {
        console.log(profile);
        User.findOrCreate({googleId: profile.id}, function(err, user) {
            return cb(err, user);
        });
    }
));

//Facebook Strategy
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets",
    profileFields: ['id', 'displayName', 'photos', 'email']
    },
    function(accessToken, refreshToken, profile, cb) {
        console.log(profile);
        User.findOrCreate({facebookId: profile.id}, function(err, user) {
            return cb(err, user);
        });
    }
));

app.get("/", function(req, res) {
    res.render("home");
});

//Google Authenticate
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    res.redirect("/secrets");
});


//Facebook Authenticate
app.get("/auth/facebook",
    passport.authenticate("facebook", {scope: ['email']})
);

app.get("/auth/facebook/secrets",
    passport.authenticate("facebook", {failureRedirect: "/login"}),
    function(req, res) {
        res.redirect("/secrets")
    }
);

app.get("/login", function(req, res) {
    res.render("login");
});

app.get("/register", function(req, res) {
    res.render("register");
});

app.get("/secrets", function(req, res) {
    User.find({"secret": {$ne: null}}, function(err, foundUsers) {
        if(err) {
            console.log(err);
        } else {
            if(foundUsers) {
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }
    })
});

app.get("/submit", function(req, res) {
    if(req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", function(req, res) {
    const submittedSecret = req.body.secret;
    const userId = req.user.id;
    
    User.findById(userId, function(err, foundUser) {
        if(err) {
            console.log(err);
        } else {
            if(foundUser) {
                foundUser.secret = submittedSecret;
                    foundUser.save(function() {
                        res.redirect("/secrets");
                    });               
            }
         }
    })
});

app.get("/logout", function(req, res) {
    req.logout();
    res.redirect("/");
});

app.post("/register", function(req, res) {
    User.register({username: req.body.username}, req.body.password, function(err, user) {
        if(err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            });
        }
    })
});

app.post("/login", function(req, res) {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err) {
        if(err) {
            console.log(err);
            res.redirect("/login");
        } else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            }) 
        }
    })
});



app.listen(3000, function(req, res) {
    console.log("Server is running on port 3000");
});