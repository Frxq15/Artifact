require('dotenv').config()
const express = require('express')
const ejs = require('ejs');
const flash = require('express-flash');
const ip = require('ip');
const app = express();
const mysql = require('mysql');
var session = require('express-session');
const bodyParser = require("body-parser");
var passport = require('passport');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
var LocalStrategy = require('passport-local');
const methodOverride = require('method-override')
var requestIp = require('request-ip');
var messagebird = require('messagebird');

initialize()
app.use(express.static(__dirname+'/public'));
app.set("view engine", "ejs");
app.set('trust proxy', true)
app.use(bodyParser.json());
app.use(flash())
app.use(bodyParser.urlencoded({
   extended: true
}));
app.use(express.urlencoded({
   extended: false
}))
app.use(flash())
app.use(session({
   secret: process.env.SESSION_SECRET,
   resave: false,
   saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())

const connection = mysql.createConnection({
   host: process.env.SQL_HOST,
   user: process.env.SQL_user,
   password: process.env.SQL_password,
   database: process.env.SQL_DB
});

connection.connect(function (error) {
   if (error) throw error
   else console.log("Connection successfull")
   try {
      let query = "CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY AUTO_INCREMENT, email VARCHAR(32) UNIQUE, username VARCHAR(16) UNIQUE, hash VARCHAR(256), salt VARCHAR(256), registered DATE, last_login TIME, last_login_ip VARCHAR(32), second_auth BOOL, second_auth_confirmed BOOL, admin BOOL);"
      connection.query(query, (e) => {
         if (e) {
            return console.error(e);
         }
      });
   } catch (e) {
      console.log(e);
   }
})

passport.use(new LocalStrategy (async function verify(username, password, cb) {
  const usernameExists = await userExists('username', username);
  if (!usernameExists) {
    return cb(null, false, {
       failureFlash: true,
       failureFlash: 'Incorrect username or password.'
    });
 }
   connection.query('SELECT * FROM users WHERE username = ?', [username], async function (err, results) {
      if (err) {
         return cb(err);
      }
      if (!results) {
         return cb(null, false, {
            failureFlash: true,
            failureFlash: 'Incorrect username or password.'
         });
      }
      const valid = await validPassword(password, results[0].hash, results[0].salt)
      console.log(valid)
      if (!valid) {
         return cb(null, false, {
            message: 'Incorrect username or password.'
         });
      }
      user = {
         id: results[0].id,
         email: results[0].email,
         username: results[0].username,
         password: results[0].password,
         second_auth: results[0].second_auth,
         registered: results[0].registered,
         last_login_ip: results[0].last_login_ip,
         admin: results[0].admin,
         second_auth_confirmed: results[0].second_auth_confirmed
      };
      return cb(null, user);
   });
}));


app.get('/', notAuthenticated, (req, res) => {
   res.render('login.ejs', {
      ip: ip.address()
   })
});
app.get('/register', notAuthenticated, (req, res) => {
   res.render('register.ejs')
})
app.get('/login', notAuthenticated, (req, res) => {
   res.render('login.ejs')
})
app.get('/user-confirm', isAuthenticated, (req, res) => {
   res.render('user-confirm.ejs', {
      name: req.user.username,
      email: req.user.email
   })
})
app.get('/index', isAuthenticated, (req, res) => {
   var dateFormat = new Date(req.user.registered);
   var formatted = dateFormat.toLocaleDateString("en-US");
   var SA = "false";
   if (req.user.second_auth) {
      SA = "Enabled";
   } else {
      SA = "Disabled";
   }
   console.log('second auth: '+req.user.second_auth)
   console.log('second auth confirmed: '+req.user.second_auth_confirmed)
   if(req.user.second_auth) {
      if(!req.user.second_auth_confirmed) {
         console.log('second auth not confirmed: '+req.user.second_auth)
      res.redirect('/user-confirm')
      return;
      }
   }
   res.render('index.ejs', {
      name: req.user.username,
      email: req.user.email,
      second_auth: SA,
      registered: formatted,
      ip: requestIp.getClientIp(req)
   })
})
app.get('/user-found', (req, res) => {
   res.render('user-found.ejs')
})
app.post('/user-confirm', isAuthenticated, secondAuthConfirmed, async (req, res) => {
   console.log('user-confirm posted for: ', req.user.username)
   await editUserDetails(req.user.username, 'second_auth_confirmed', true)
   res.redirect('/index')
   console.log('redirected to /index')
})
app.post("/logout", (req, res) => {
   req.logout(req.user, err => {
      if (err) return next(err);
      res.redirect("/");
   });
});

app.post("/change-password", async (req, res) => {
   const hashedPassword = await genPassword(req.body.password);
   await editUserDetails(req.user.username, 'hash', hashedPassword.hash)
   await editUserDetails(req.user.username, 'salt', hashedPassword.salt)
  req.logout(req.user, err => {
     if (err) return next(err);
     res.redirect("/");
  });
});


app.post('/login', notAuthenticated, passport.authenticate('local', {
   successRedirect: '/index',
   failureRedirect: '/login',
   failureFlash: true
}))

app.post('/register', async (req, res, next) => {
   var currentTime = new Date();

   const emailExists = await userExists('email', req.body.email);
   const usernameExists = await userExists('username', req.body.username);

   if (emailExists || usernameExists) {
      res.redirect('/user-found')
      return;
   }
   const password = await genPassword(req.body.password);
   let query = `INSERT into users (email, username, hash, salt, registered, last_login, last_login_ip, second_auth, second_auth_confirmed, admin) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?,?);`
   try {
      connection.query(query, [req.body.email, req.body.username, password.hash, password.salt, currentTime, null, requestIp.getClientIp(req), 0, 0, 0]), (e) => {
         if (e) throw e
         console.log(e)
      }
      console.log('Created entry for User: ' + req.body.username + ' (Email: ' + req.body.email + ') successfully.');
      res.redirect('/login')
   } catch (e) {
      console.log(e)
      res.redirect('/register')
   }
});

async function userExists(type, data) {
   return new Promise((resolve, reject) => {
      let query = "SELECT " + type + " FROM users WHERE " + type + "=?"
      connection.query(query, [data], (e, results) => {
         if (results.length < 1) {
            console.log(e)
            resolve(false)
         } else {
            resolve(true);
         }
      });
   });
}

async function editUserDetails(username, type, data) {
  try {
    console.log(username)
     let query = "UPDATE users SET "+type+"=? WHERE username=?"
     connection.query(query, [data, username], (e) => {
        if (e) {
           return console.error(e);
        }
        console.log('details updated for user '+username+ ': '+type+' updated to '+data)
     });
  } catch (e) {
     console.log(e);
  }
}

passport.serializeUser(function (user, done) {
   console.log('user :' + user + " id: " + user.id)
   done(null, user.id);
});

passport.deserializeUser(function (user, done) {
   console.log(user);
   connection.query('SELECT * FROM users where id = ?', [user], function (error, results) {
      done(null, results[0]);
   });
});

function isAuthenticated(req, res, next) {
   if (req.isAuthenticated()) {
      return next()
   }
   res.redirect('/login')
}
function secondAuthConfirmed(req, res, next) {
   if (!req.user.second_auth_confirmed) {
      return next()
   }
   res.redirect('/')
}

function notAuthenticated(req, res, next) {
   if (req.isAuthenticated()) {
      return res.redirect('/index')
   }
   next()
}

async function validPassword(password,hash,salt)
{
    var hashVerify = await crypto.pbkdf2Sync(password,salt,10000,60,'sha512').toString('hex');
    return hash === hashVerify;
}
async function genPassword(password)
{
    var salt=crypto.randomBytes(32).toString('hex');
    var genhash = crypto.pbkdf2Sync(password,salt,10000,60,'sha512').toString('hex');

    return {salt:salt,hash:genhash};
}

function initialize() {
   let port = 5000;
   app.listen(port)
   console.log('Server started on: ' + 'http://localhost:' + port)
}