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
var LocalStrategy = require('passport-local');

initialize()
app.use(express.static('public'));
app.set("view engine", "ejs");
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.urlencoded({ extended: false }))
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

connection.connect(function(error) {
if(error) throw error
else console.log("Connection successfull")
try {
  let query = "CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY AUTO_INCREMENT, email VARCHAR(32) UNIQUE, username VARCHAR(16) UNIQUE, password CHAR(60), registered DATE, last_login TIME, second_auth BOOL);"
  connection.query(query, (e) => {
    if (e) {
      return console.error(e);
    }
  });
} catch(e) {
  console.log(e);
}
})

passport.use(new LocalStrategy(function verify(username, password, cb) {
  connection.query('SELECT * FROM users WHERE username = ?', [ username ], function(err, results) {
    if (err) { return cb(err); }
    if (!results) { return cb(null, false, { message: 'Incorrect username or password.' }); }

      if (password !== results[0].password) {
        return cb(null, false, { message: 'Incorrect username or password.' });
      }
      user={id:results[0].id,email:results[0].email,username:results[0].username,password:results[0].password};
      return cb(null, user);
  });
}));


app.get('/', (req, res) => {
    res.render('login.ejs', { ip: ip.address()})
});
app.get('/register', (req, res) => {
    res.render('register.ejs')
  })
  app.get('/login', (req, res) => {
    res.render('login.ejs')
  })
  app.get('/index', (req, res) => {
    res.render('index.ejs', { name: req.user.username })
  })
  app.get('/user-found', (req, res) => {
    res.render('user-found.ejs')
  })

  app.post('/login', passport.authenticate('local', {
    successRedirect: '/index',
    failureRedirect: '/login',
  }))

  app.post('/register', async (req,res,next)=>{
    var currentTime = new Date();

    const emailExists = await userExists('email', req.body.email);
    const usernameExists = await userExists('username', req.body.username);

    if(emailExists || usernameExists) {
      res.redirect('/user-found')
      return;
    }

    let query = `INSERT into users (email, username, password, registered, last_login, last_login_ip, second_auth) VALUES (?, ?, ?, ?, ?, ?, ?);`
    try {
    connection.query(query, [req.body.email, req.body.username, req.body.password, currentTime, null, 0, 0]), (e) => {
      if(e) throw e
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
      let query = "SELECT "+type+" FROM users WHERE "+type+"=?"
      connection.query(query, [ data ], (e, results) => {
          if (results.length < 1) {
              console.log(e)
              resolve(false)
          } else {
          resolve(true);
          }
      });
  });
}

passport.serializeUser(function(user, done) {
  console.log('user :'+user + " id: " + user.id)
  done(null, user.id);
});

passport.deserializeUser(function(user,done){
  console.log(user);
  connection.query('SELECT * FROM users where id = ?',[user], function(error, results) {
          done(null, results[0]);    
  });
});

function initialize() {
    let port = 5000;
    app.listen(port)
    console.log('Server started on: '+'http://localhost:'+port)
}