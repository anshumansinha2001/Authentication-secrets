//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const { log } = require('console');
const FacebookStrategy = require("passport-facebook")

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb+srv://anshumansinha:Test-123@cluster0.10q55qu.mongodb.net/userDB", { useNewUrlParser: true, useUnifiedTopology: true });





const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String, // Add facebookId field
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// User model of schema
const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id)
        .exec()
        .then((user) => {
            done(null, user);
        })
        .catch((err) => {
            done(err, null);
        });
});


// Passport for Google Login
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile);
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));


// Passport for FaceBook Login
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ facebookId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

app.get("/", (req, res) => {
    res.render("home");
});

app.get("/auth/google", (req, res) => {
    passport.authenticate("google", { scope: ["profile"] })(req, res);
});

app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect to the secrets page.
        res.redirect("/secrets");
    });



app.get('/auth/facebook',
    passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect to the secrets page.
        res.redirect("/secrets");
    });


app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/logout", (req, res) => {
    req.logout(function (err) {
        if (err) {
            console.log(err);
        }
        res.redirect("/");
    });
});


function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect("/login");
}
app.get("/submit", ensureAuthenticated, (req, res) => {
    res.render("submit");
});

app.post("/submit", ensureAuthenticated, async (req, res) => {
    const submittedSecret = req.body.secret;

    try {
        // Use async/await to find the user by ID
        const foundUser = await User.findById(req.user.id).exec();

        if (foundUser) {
            foundUser.secret = submittedSecret;
            await foundUser.save();
            res.redirect("/secrets");
        } else {
            res.status(404).send("User not found");
        }
    } catch (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
    }
});



app.get("/secrets", ensureAuthenticated, async (req, res) => {
    try {
        // Use async/await to find users with secrets
        const usersWithSecrets = await User.find({ secret: { $ne: null } }).exec();

        res.render("secrets", { userWithSecrets: usersWithSecrets });
    } catch (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
    }
});


app.get("/submit", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login")
    }
});

app.post("/register", async (req, res) => {

    User.register(new User({ username: req.body.username }), req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate('local')(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });
});


app.post("/login", async (req, res) => {
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
    });
});






app.listen(3000, () => {
    console.log("Server started on port 3000.");
});







// const encrypt = require("mongoose-encryption");
// const md5 = require('md5');
// const bcrypt = require('bcrypt');
// const saltRounds = 10;




// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["passowrd"] });



// app.post("/register", async (req, res) => {
//     try {
//         const hash = await bcrypt.hash(req.body.password, saltRounds);
//         const newUser = new User({
//             email: req.body.username,
//             password: hash
//         });
//         await newUser.save();
//         res.render("secrets");
//     } catch (err) {
//         console.log(err);
//         res.status(500).send("Registration failed. Please try again.");
//     }
// });



// app.post("/login", async (req, res) => {
//     const username = req.body.username;
//     const password = req.body.password;

//     try {
//         const foundUser = await User.findOne({ email: username }).exec();
//         if (foundUser) {
//             // Compare the input password with the hashed password using bcrypt.compare
//             const passwordMatch = await bcrypt.compare(password, foundUser.password);
//             if (passwordMatch) {
//                 res.render("secrets");
//             } else {
//                 // Password doesn't match
//                 // You can provide appropriate error handling or redirect to a login failure page
//             }
//         } else {
//             // User not found
//             // You can provide appropriate error handling or redirect to a login failure page
//         }
//     } catch (err) {
//         console.log(err);
//         // Handle the error as needed
//     }
// });