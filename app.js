require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
require('dotenv').config()
const app = express();
app.use(bodyParser.urlencoded({
    extended: true
}));
const ejs = require("ejs");
const {
    default: mongoose
} = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');


app.set("view engine", "ejs");
app.use(express.static("public"));

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(`mongodb+srv://jasmin:${process.env.PW}@cluster0.yqjaf.mongodb.net/userDB`);

var usersSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

usersSchema.plugin(passportLocalMongoose);
usersSchema.plugin(findOrCreate);

const User = new mongoose.model("User", usersSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
    done(null, user.id);
});
passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "https://sleepy-depths-26400.herokuapp.com/auth/google/secrets",
        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({
            username: profile.emails[0].value,
            googleId: profile.id,
        }, function (err, user) {
            return cb(err, user);
        });
    }
));


const getDate = new Date();
const calcYear = getDate.getFullYear();


app.get("/", function (req, res) {
    res.render("home", {
        year: calcYear
    });
});

app.get("/login", function (req, res) {
    res.render("login", {
        year: calcYear
    });
});


app.get("/register", function (req, res) {
    res.render("register", {
        year: calcYear
    });
});

//cookies- check login for not again loggin 
//rendering all secrets from db
app.get("/secrets", function (req, res) {
    // if (req.isAuthenticated()) {
    //     res.render("secrets", {
    //         year: calcYear
    //     });
    // } else {
    //     res.redirect("/login");
    // }
    User.find({
        "secret": {
            $ne: null
        }
    }, function (err, foundUser) {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                res.render("secrets", {
                    userWithSecret: foundUser,
                    year: calcYear
                });
            }
        }
    });
});

app.get("/logout", function (req, res) {
    req.logout();
    res.redirect("/");
});

//safe username and pw -> get authenticated while registered
app.post("/register", function (req, res) {

    User.register({
        username: req.body.username
    }, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });
});

//get authenticated while login
app.post("/login", function (req, res) {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function (err) {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    })
});


//pop up to connect with google auth
app.get('/auth/google',
passport.authenticate('google', { scope: ['profile',"email"] }));

//after clicked at a google acc
app.get("/auth/google/secrets",
    passport.authenticate("google", {
        failureRedirect: "/login"
    }),
    function (req, res) {
        //successfully authenticated, redirect home
        res.redirect("/secrets");
    });



//submit Secrets
app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("submit", {
            year: calcYear
        });
    } else {
        res.redirect("/login");
    }
});


app.post("/submit", function (req, res) {
    const submittedSecret = req.body.secret;

    User.findById(req.user._id, function (err, foundUser) {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save(function () {
                    res.redirect("/secrets");
                });
            }
        }
    });
});

let port = process.env.PORT || 3000;
if (port == null || port == "") {
    port = 3000;
}

app.listen(port, function () {
    console.log("Server successfully started");
});


//summary:
// -if user hits button that href to /auth/google/
// -which gets caught ind app.get... -> initiate authentication on googles servers asking for users profile
// -if successfull redirect to auth/google/secrets -> that code part will authenticate locally and save login session
// -once they were successfully authenticated the get rendered to /secrets