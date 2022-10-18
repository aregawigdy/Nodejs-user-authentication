const express = require('express');
const app = express();
const { pool } = require('./dbConfig');
const bcrypt = require('bcrypt');
const session = require('express-session');
const flash = require('express-flash');
const passport = require('passport');

const initializePassport = require('./passportConfig');

initializePassport(passport);

const PORT = 4000;

app.set("view engine", "ejs");
app.use(express.urlencoded({extended: false}));
app.use(express.static('assets'));

app.use(
    session({
        secret: "secret",

        resave: false,

        saveUninitialized: false
    })
);

app.use(passport.initialize());
app.use(passport.session());

app.use(flash());
app.get('/', checkAuthenticated, (req, res) => {
    res.render("index");
});

app.get('/users/register', checkAuthenticated, (req, res) => {
    res.render("register");
});

app.get('/users/dashboard', checkNotAuthenticated, (req, res) => {
    res.render("dashboard", {user: req.user.first_name});
});

app.get('/users/logout', function(req, res, next) {
    req.logout(function (err){
        if(err){
            return next(err);
        }
        req.flash("success_msg", "You have logged out");
        res.redirect('/');
    });    
});

app.post('/users/register', async(req, res) => {
    let {first_name, last_name, email, password, role, company, department } = req.body;

    console.log({
        first_name,
        last_name,
        email,
        password,
        role,
        company,
        department
    });

    let errors = [];
    if(!first_name || !last_name || !email || !password || !role || !company || !department) {
        errors.push({message: "Please enter all fields"});
    }

    if(password.length < 6){
        errors.push({message: "Password should be at least 6 characters"});
    }

    if(errors.length > 0){
        res.render("register", {errors});
    } else{
        let hashedpwd = await bcrypt.hash(password, 5);
        console.log(hashedpwd);

        pool.query("SELECT * FROM users WHERE email = $1", [email], 
        (err, results) => {
            if(err){
                throw err;
            }

            console.log(results.rows);

            if(results.rows.length > 0){
                errors.push({message: "User is already available"});
                res.render("register", {errors});
            } else{
                pool.query("INSERT INTO users (first_name, last_name, email, password, role, company, department) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, password", [first_name, last_name, email, hashedpwd, role, company, department], (err, results) => {
                    if(err){
                        throw err;
                    }
                    console.log(results.rows);
                    req.flash("success_msg", "You are registered, please login");
                    res.redirect("/");
                })
            }
         }
        );
    }
});

app.post(
    '/', passport.authenticate('local', {
        successRedirect: '/users/dashboard',
        failureRedirect: '/',
        failureFlash: true
    })
);

function checkAuthenticated(req, res, next){
    if(req.isAuthenticated()){
        return res.redirect('/users/dashboard');
    }
    next();
}

function checkNotAuthenticated(req, res, next){
    if(req.isAuthenticated()){
        return next();
    }
    res.redirect('/');
}

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});