require('dotenv').config()
const express = require('express')
const ejs = require('ejs');
const flash = require('express-flash');
const ip = require('ip');
const app = express();
const mysql = require('mysql');
var session = require('express-session');
const nodemailer = require('nodemailer');
const bodyParser = require("body-parser");
var passport = require('passport');
const crypto = require('crypto');
var LocalStrategy = require('passport-local');
const methodOverride = require('method-override')
var requestIp = require('request-ip');
var messagebird = require('messagebird')(process.env.MESSAGE_BIRD_API_KEY)
var alert = require('alert');
var expresshbs = require('express-handlebars');
const Recaptcha = require('express-recaptcha').RecaptchaV3;
const recaptcha = new Recaptcha('6LeG6AwmAAAAANf4m6Xo1N9PoqBvzQqcBKHgkvNQ', '6LeG6AwmAAAAANMHKUsHoz38Iio9eX7I4mZT4bVy');

const transporter = nodemailer.createTransport({
   service: 'Gmail',
   auth: {
     user: process.env.GMAIL_EMAIL,
     pass: process.env.GMAIL_PASS
   }
 });

initialize()
app.use(express.static(__dirname+'/public'));
app.set("view engine", "ejs");
app.set('trust proxy', true)
app.use(bodyParser.json());
app.use(flash())
app.use(bodyParser.urlencoded({
   extended: true
}));
app.use(methodOverride('X-HTTP-Method-Override'))
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
   if (error) {
      throw error;
   } 
   console.log("Connected to MySQL successfully.")
   try {
      let query = "CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY AUTO_INCREMENT, email VARCHAR(32) UNIQUE, username VARCHAR(16) UNIQUE, hash VARCHAR(256), salt VARCHAR(256), registered DATE, last_login TIME, last_login_ip VARCHAR(32), second_auth BOOL, second_auth_confirmed BOOL, admin BOOL, account_status VARCHAR(16));"
      connection.query(query, (e) => {
         if (e) {
            return console.error(e);
         }
      });
   } catch (e) {
      console.log(e);
   }
   try {
      let query = "CREATE TABLE IF NOT EXISTS logs (username VARCHAR(16), email VARCHAR(32), type VARCHAR(32), timestamp DATETIME, ip VARCHAR(32), additional_info VARCHAR(256));"
      connection.query(query, (e) => {
         if (e) {
            return console.error(e);
         }
      });
   } catch (e) {
      console.log(e);
   }
})

function getCurrentDateTime() {
   var date = new Date();
   var datetime = date.toISOString().slice(0, 19).replace('T', ' ');
   return datetime;
}

async function createLog(req, type, misc) {
   let query = `INSERT into logs (username, email, type, timestamp, ip, additional_info) VALUES (?, ?, ?, ?, ?, ?);`
         try {
            connection.query(query, [req.user.username, req.user.email, type, getCurrentDateTime(), requestIp.getClientIp(req), misc]), (e) => {
               if (e) throw e;
               console.log(e)
            }
         } catch (e) {
            console.log(e)
         }
}
//for logging without a request handler
async function createLog2(user, email, ip, type, misc) {
   let query = `INSERT into logs (username, email, type, timestamp, ip, additional_info) VALUES (?, ?, ?, ?, ?, ?);`
         try {
            connection.query(query, [user, email, type, getCurrentDateTime(), ip, misc]), (e) => {
               if (e) throw e;
               console.log(e)
            }
         } catch (e) {
            console.log(e)
         }
}

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
         account_status: results[0].account_status,
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
app.get('/page-not-found', (req, res) => {
   res.render('page-not-found.ejs')
})
app.get('/register', notAuthenticated, (req, res) => {
   res.render('register.ejs')
})
app.get('/login', notAuthenticated, (req, res) => {
   res.render('login.ejs')
})
app.get('/admin', isAuthenticated, (req, res) => {
   if(!isAdmin(req)) {
      res.redirect('page-not-found')
      return;
   }
   res.render('admin.ejs', {
      name: req.user.username
   })
})
app.get('/logs', isAuthenticated, (req, res) => {
   if(!isAdmin(req)) {
      res.redirect('page-not-found')
      return;
   }//
   connection.query('SELECT * FROM logs ORDER by timestamp DESC', function (err, result) {
      if (err) throw err;

      ///res.render() function
      res.render('logs.ejs', {
         data: result,
         name: req.user.username
      });
      createLog(req, 'ADMIN-ACCESS', 'Admin viewed logs page.')
    });
})
app.get('/users', isAuthenticated, (req, res) => {
   if(!isAdmin(req)) {
      res.redirect('page-not-found')
      return;
   }//
   connection.query('SELECT username,email,registered,last_login,last_login_ip,second_auth,admin,account_status FROM users ORDER by username', function (err, result) {
      if (err) throw err;

      ///res.render() function
      res.render('users.ejs', {
         data: result,
         name: req.user.username
      });
      createLog(req, 'ADMIN-ACCESS', 'Admin viewed user-management page.')
    });
})
app.get('/user-confirm', isAuthenticated, secondAuthConfirmed, (req, res) => {
   res.render('user-confirm.ejs', {
      name: req.user.username,
      email: req.user.email
   })
   transporter.sendMail(send2fa(req.user.email), function(error, info){
      if (error) {
        console.log(error);
      } else {
        console.log('Email sent: ' + info.response);
      }
    });
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
   createLog(req, 'USER-LOGIN', 'User logged in successfully.')
})
app.get('/user-found', notAuthenticated, (req, res) => {
   res.render('user-found.ejs')
})
app.get('/user-not-found', notAuthenticated, (req, res) => {
   res.render('user-not-found.ejs')
})
app.post('/user-confirm', isAuthenticated, secondAuthConfirmed, async (req, res) => {
   console.log('user-confirm posted for: ', req.user.username)
   await editUserDetails(req.user.username, 'second_auth_confirmed', true)
   res.redirect('/index')
   console.log('redirected to /index')
})
app.post("/logout", async (req, res) => {
   await editUserDetails(req.user.username, 'second_auth_confirmed', false)
   req.logout(req.user, err => {
      if (err) return next(err);
      res.redirect("/");
   });
});

function isAdmin(req) {
   if(req.user.admin) {
      return true;
   }
   return false;
}

app.post("/change-password", async (req, res) => {
   const hashedPassword = await genPassword(req.body.password);
   await editUserDetails(req.user.username, 'hash', hashedPassword.hash)
   await editUserDetails(req.user.username, 'salt', hashedPassword.salt)
  req.logout(req.user, err => {
     if (err) return next(err);
     res.redirect("/");
  });
});

app.post('/login', notAuthenticated, recaptcha.middleware.verify, (req, res) => {
   console.log(req.recaptcha)
   if (req.recaptcha.error) {
      console.log("Recaptcha error: " + req.recaptcha.error)
      res.redirect("/");
      return;
   }
   passport.authenticate('local',  {
   successRedirect: '/index',
   failureRedirect: '/user-not-found',
   failureFlash: true,
})
})

app.post('/register', async (req, res, next) => {
   var currentTime = new Date();

   const emailExists = await userExists('email', req.body.email);
   const usernameExists = await userExists('username', req.body.username);

   if (emailExists || usernameExists) {
      res.redirect('/user-found')
      return;
   }
   const password = await genPassword(req.body.password);
   let query = `INSERT into users (email, username, hash, salt, registered, last_login, last_login_ip, second_auth, second_auth_confirmed, admin, account_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?,?,?);`
   try {
      connection.query(query, [req.body.email, req.body.username, password.hash, password.salt, currentTime, null, requestIp.getClientIp(req), 0, 0, 0, 'Registered']), (e) => {
         if (e) throw e
         console.log(e)
      }
      console.log('Created entry for User: ' + req.body.username + ' (Email: ' + req.body.email + ') successfully.');
      createLog2(req.body.username, req.body.email, requestIp.getClientIp(req), 'USER-SIGNUP', 'User created successfully.')
      console.log('Username: ' + req.body.username)
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
  if(type.toString().toLowerCase() == 'password') {
   createLog2(username, getUserDetails(username).email, getUserDetails(username).last_login_ip, 'USER-PASSWORD-CHANGE', 'User password changed successfully.')
   return;
  }
  if(type.toString().toLowerCase() == 'second_auth_confirmed') {
   return;
  }
  createLog2(username, getUserDetails(username).email, getUserDetails(username).last_login_ip, 'USER-EDIT-DETAILS', type + ' was changed to ' + data)
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

 function send2fa(email) {
 return mailOptions = {
   from: 'cxrtwrightdan15@gmail.com',
   to: email,
   subject: 'Your 2FA code',
   text: `Your 2FA code is: 200`
 };
}

async function getUserDetails(username) {
   return new Promise((resolve, reject) => {
       connection.query('SELECT * FROM users WHERE username = ?', [username], async function (err, results) {
          if (err) {
             reject(err)
          }
          if (!results) {
             return reject(err)
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
         resolve(user)
            })
          });
         }


      function deleteUser(username) {
         console.log('deleteUser', username)
         try {
            console.log(username)
             let query = "DELETE from users WHERE username=?"
             connection.query(query, [username], (e) => {
                if (e) {
                   return console.error(e);
                }
                console.log('deleted '+username)
             });
          } catch (e) {
             console.log(e);
          }
      }
      app.get('/users/delete/:username', function(req, res, next) {
         console.log('params '+req.params.username)
         if(req.user.username == req.params.username) {
            res.redirect('/users')
            return;
         }
         if(getUserDetails(req.params.username).admin) {
            res.redirect('/users')
            return;
         }
         deleteUser(req.params.username)
         createLog2(req.user.username, getUserDetails(req.user.username).email, getUserDetails(username).last_login_ip, 'USER-DELETE', 'Deleted the user '+req.params.username)
         res.redirect('/users')
      })

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
   

      //404 IS RIGHT HERE
app.get('*', function(req, res){
   res.status(404).render('page-not-found.ejs');
 });

function initialize() {
   let port = 5000;
   app.listen(port)
   console.log('Server started on: ' + 'http://localhost:' + port)
}