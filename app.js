//jshint esversion:6
require("dotenv").config();
const express= require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
//passport-local-mongoose depend on passport-local
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require('mongoose-findorcreate');

var GoogleStrategy = require('passport-google-oauth20').Strategy;


// const encrypt = require("mongoose-encryption");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({
  extended:true
}));

app.use(session({
  secret:process.env.SECRET,
  resave:false,
  saveUninitialized:false
}));

app.use(passport.initialize());
app.use(passport.session());
const url = process.env.URL;
mongoose.connect(url,{useNewUrlParser:true,useUnifiedTopology: true});
mongoose.set("useCreateIndex",true);

const userSchema=new mongoose.Schema({
  username:String,
  password:String,
  googleId:String,
  secret:[String]
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
//encrypt before creating model
// userSchema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields: ["password"]});

const User = new mongoose.model("User",userSchema)

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/mysecretnotes"
  },
  function(accessToken, refreshToken, profile, cb) {

    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",function(req,res){
  res.render("home");
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] }));

  app.get("/auth/google/mysecretnotes",
    passport.authenticate("google", { failureRedirect: "/login" }),
    function(req, res) {
      // Successful authentication, redirect secrets.
      res.redirect("/secrets");
    });

app.get("/register",function(req,res){
  res.render("register",{regMessage:null});
});

app.get("/login",function(req,res){
  res.render("login");
});

app.get("/secrets",function(req,res){

  if(req.isAuthenticated()){
    User.findById(req.user.id,function(err,foundUser){
      if(err){
        next(err);
      }else{
        if(foundUser){
            res.render("secrets",{userWithSecrets:foundUser.secret});
          }
          else{
            res.redirect("/login");
          }
      }
    });
  }
});



app.get("/submit",function(req,res){
  if(req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("/login");
  }
});

app.get("/logout",function(req,res){
  req.logout();
  req.session = null;
  res.redirect("/");
});



app.post("/register",function(req,res){
  User.register({username:req.body.username},req.body.password,function(err,user){
    if(err){
      res.render("register",{regMessage:err.message});
    }else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      })
    }
  })

});

app.post("/login", function(req, res,next){
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  passport.authenticate('local', function(err, user, info) {
    if (err) {
       return next(err);
     }
    if (!user) {
      return res.redirect('/login');
    }
    // req / res held in closure
    req.logIn(user, function(err) {
      if (err) {
        return next(err);
      }
      return res.redirect("/secrets");
    });

  })(req, res, next);


});

app.post("/submit",function(req,res){
  const submittedNewSecret = req.body.secret;
  // console.log(req.user.id);

  User.findById(req.user.id,function(err,foundUser){
    if(err){
      next(err);
    }else{
      if(foundUser){
        foundUser.secret.push(submittedNewSecret);
        foundUser.save(function(){
          res.redirect("/secrets");
        })
      }
    }
  })
})


app.listen(process.env.PORT||3000,function(){
  console.log("server start at 3000");
})
