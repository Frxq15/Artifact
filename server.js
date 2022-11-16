require('dotenv').config()
const express = require('express')
const ejs = require('ejs');
const flash = require('express-flash');
const ip = require('ip');
const app = express();
const mysql = require('mysql');
var session = require('express-session');
const bodyParser = require("body-parser");

initialize()
app.use(express.static('public'));
app.set("view engine", "ejs");
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
  extended: true
}));

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


app.get('/', (req, res) => {
    res.render('login.ejs', { ip: ip.address()})
});
app.get('/register', (req, res) => {
    res.render('register.ejs')
  })
  app.get('/login', (req, res) => {
    res.render('login.ejs')
  })

  app.post('/register', async (req,res,next)=>{
    var currentTime = new Date();

    const emailExists = await userExists('email', req.body.email);
    const usernameExists = await userExists('username', req.body.username);

    console.log(emailExists)

    if(emailExists || usernameExists) {
      console.log('user already exists')
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
        console.log(results)
          if (e) {
            console.log('failed')
              console.log(e)

          }
          console.log('passed')
          resolve(true);
      });
  });
}



function initialize() {
    let port = 5000;
    app.listen(port)
    console.log('Server started on: '+'http://localhost:'+port)
}