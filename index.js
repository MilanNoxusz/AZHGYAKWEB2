const passport=require('passport');
const LocalStrategy=require('passport-local').Strategy;
const express = require('express');
const app = express();
const bodyParser = require("body-parser");
const mysql = require('mysql2');
const crypto=require('crypto');
var session = require('express-session');
var MySQLStore = require('express-mysql-session')(session);

app.use(session({
key: 'session_cookie_name', // ezt használjuk a Cookie-ban
secret: 'session_cookie_secret',
// A datbázisban tároljuk a Session adatokat:
store: new MySQLStore({
host:'localhost',
user:'root',
password: "",
database:'zh_gyakorlas'
}),
resave: false,
saveUninitialized: false,
cookie:{
maxAge:1000*60*60*24,
}
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
extended: true
}));
app.use(express.static('public'));
app.set("view engine", "ejs");

var connection = mysql.createConnection({
host: "localhost",
user: "root",
password: "",
database: "zh_gyakorlas",
multipleStatements: true
});
connection.connect((err) => {
if (!err)
console.log("Connected");
else
console.log("Conection Failed");
});
// A felhasználók bejelentkezési neve és jelszava:
const customFields={
usernameField:'uname',
passwordField:'pw',
};

const verifyCallback=(username,password,done)=>{
connection.query('SELECT * FROM users WHERE username = ? ', [username], function(error, results, fields) {
if (error)
return done(error);
if(results.length==0)
return done(null,false);
const isValid=validPassword(password,results[0].hash);
user={id:results[0].id,username:results[0].username,hash:results[0].hash};
if(isValid)
return done(null,user);
else
return done(null,false);
});
}
const strategy=new LocalStrategy(customFields,verifyCallback);
passport.use(strategy);

passport.serializeUser((user,done)=>{
console.log("inside serialize");
done(null,user.id)
});
passport.deserializeUser(function(userId,done){
console.log('deserializeUser'+ userId);
connection.query('SELECT * FROM users where id = ?',[userId], function(error, results) {
done(null, results[0]);
});
});

function validPassword(password,hash)
{
var hashVerify=crypto.createHash('sha512').update(password).digest('hex');
return hash === hashVerify;
}
function genPassword(password)
{
return crypto.createHash('sha512').update(password).digest('hex');
}



function isAuth(req,res,next)
{
if(req.isAuthenticated())
next();
else
res.redirect('/notAuthorized');
}
function userExists(req,res,next)
{
// ?: preparált lekérdezés: Web-1-ben tanultuk
// ? <= [req.body.uname]
connection.query('Select * from users where username=? ', [req.body.uname], function(error, results, fields) {
if (error)
console.log("Error");
else if(results.length>0)
res.redirect('/userAlreadyExists')
else
next();
});
}

app.use((req,res,next)=>{
console.log(req.session);
console.log(req.user);
next();
});

/*routes*/
app.get('/login', (req, res, next) => {
res.render('login') // ez a next()
});

app.get('/logout', function(req, res, next) {
// kiüríti a session táblát:
req.session.destroy(function (err) {
// Törli a Cookie-t:
res.clearCookie('session_cookie_name');
res.redirect('/');
});
});


app.get('/login-success', (req, res, next) => {
res.redirect('/protected-route');
});


app.get('/login-failure', (req, res, next) => {
res.send('You entered the wrong password.');
});


app.get('/register', (req, res, next) => {
console.log("Inside get");
res.render('register')
});


app.post('/register',userExists,(req,res,next)=>{
// ha nem szerepel az adatbázisban, akkor a jelszó elkészítése után beírjuk az adatbázisba:
console.log("Inside post");
console.log(req.body.pw);
const hash=genPassword(req.body.pw);
console.log(hash);
// ?: preparált utasítás
// ?,? <= [req.body.uname,hash] 0: isAdmin
connection.query('Insert into users(username,hash,isAdmin) values(?,?,0) ', [req.body.uname,hash], function(error, results, fields) {
if (error)
console.log("Error");
else
console.log("Successfully Entered");
});
res.redirect('/login');
});

app.post('/login',passport.authenticate('local',{failureRedirect:'/login-failure',successRedirect:'/login-success'}));
app.get('/', (req, res, next) => {
auth=false
username=""
admin=false
if(req.isAuthenticated()){
auth=true
username=req.user.username
}
if(req.isAuthenticated() && req.user.isAdmin==1)
admin=true
res.render("mainpage", {
isAuth: auth, isAdmin: admin, username: username
});
});

app.get('/protected-route',isAuth,(req, res, next) => {
admin=false
if(req.isAuthenticated() && req.user.isAdmin==1)
admin=true
res.render("protected", {
isAdmin: admin, username: req.user.username
});
});


app.get('/userAlreadyExists', (req, res, next) => {
console.log("Inside get");
res.send('<h1>Sorry This username is taken </h1><p><a href="/register">Register with different username</a></p>');
});
app.get('/notAuthorized', (req, res, next) => {
console.log("Inside get");
res.send('<h1>You are not authorized to view the resource </h1><p><a href="/login">Retry Login</a></p>');
});
app.get('/notAuthorizedAdmin', (req, res, next) => {
console.log("Inside get");
res.send('<h1>You are not authorized to view the resource as you are not the admin of the page </h1><p><a href="/login">Retry to Login as admin</a></p>');
});
app.listen(3000, function() {
console.log('App listening on port 3000!')
});

