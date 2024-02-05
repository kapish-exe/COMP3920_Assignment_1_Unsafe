require('./utils');

const express = require('express');
require('dotenv').config();
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 10;

const app = express();

const port = process.env.PORT || 3000;
const expireTime = 1000 * 60 * 60; // 1 hour
const database = include('databaseConnection');
const db_utils = include('database/db_utils');
const db_users = include('database/users');

const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@cluster0.lbwzy87.mongodb.net/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({
	secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false,
	resave: true
}
));

function isValidSession(req) {
	if (req.session.authenticated) {
		return true;
	}
	return false;
}

function sessionValidation(req, res, next) {
	if (!isValidSession(req)) {
		req.session.destroy();
		res.redirect('/login');
		return;
	}
	else {
		next();
	}
}

app.get('/', async (req, res) => {
	if (isValidSession(req)) {
		res.render('loggedin', { username: req.session.username });
	} else {
		res.render('index');
	}
});

app.get('/signup', (req, res) => {
	res.render('signup', {error: ''});
});

app.post('/submit_user', async (req, res) => {
	const username = req.body.username;
	const password = req.body.password;

	// Check if any field is empty
	if (!username || !password) {
		const missingField = !username ? 'username' : 'password';
		res.render('signup', { error: `Please enter ${missingField}` });
		return;
	}

	try {
		const hashedPassword = await bcrypt.hash(password, saltRounds);
		await db_users.createUser({ user: username, hashedPassword: hashedPassword });
		console.log('User created');
	  } catch (error) {
		console.error('Error creating user:', error);
		res.status(500).send('Internal Server Error');
	  }

	res.redirect('/login');
});

app.get('/login', (req, res) => {
	res.render('login', { error: '' });
});


app.post('/loggingin', async (req,res) => {
    var username = req.body.username;
    var password = req.body.password;

	// if (!username || !password) {
	// 	const missingField = !username ? 'username' : 'password';
	// 	res.render('login', { error: `Please enter ${missingField}` });
	// 	return;
	// }


    var results = await db_users.getUser({ user: username, hashedPassword: password });

    if (results) {
        if (results.length == 1) { //there should only be 1 user in the db that matches
            if (bcrypt.compareSync(password, results[0].password)) {
                req.session.authenticated = true;
                req.session.user_type = results[0].type; 
                req.session.username = username;
                req.session.cookie.maxAge = expireTime;
				
				res.redirect('/members');
                return;
            }
            else {
                console.log("invalid password");
            }
        }
        else if (results.length > 1){
            console.log('invalid number of users matched: '+results.length+" (expected 1).");
            res.render('injection', {users:results});
            return;            
        }
    }

    console.log('user not found');
    //user and password combination not found
    res.redirect("/login");
});


app.get('/logout', (req, res) => {
	req.session.destroy();
	res.redirect('/');
});

app.get('/members', sessionValidation, (req, res) => {
	const username = req.session.username;
	id = Math.floor(Math.random() * 3) + 1;
	res.render('members', { username, id });

});

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.render("404");
})

app.listen(port, () => {
	console.log(`Server started on http://localhost:${port}`);
});