require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const saltRounds = 12;
const app = express();
app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }));

// parse application/json
app.use(bodyParser.json());


const port = process.env.PORT || 3000;


const Joi = require("joi");

const urlencoded = require('url');

const images = ["1.png", "2.png", "3.png"];


const expireTime = 60 * 60 * 1000; // one hour 1 hour * 60 minutes/hour * 60 seconds/minute * 1000 milliseconds/second

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

const client = require("./databaseConnection");

const userCollection = client.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));
app.use(express.static(__dirname + "/../public"));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/assignment2`,
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

const nav = [
    { label: "Home", path: "/" },
    { label: "Members", path: "/loggedin" },
    { label: "Admin", path: "/admin" },
];

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function mainPageLogIn(req,res) {
    if (isValidSession(req)) {
        res.render('index', {name: req.session.username, log: 'logout', nav: nav, currentURL: urlencoded.parse(req.url).pathname});
    }
    else {
        res.render('index', {name: req.session.username, log: 'login', nav: nav, currentURL: urlencoded.parse(req.url).pathname});
    }
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errors", {error: "Not Authorized", nav: nav, currentURL: urlencoded.parse(req.url).pathname});
        return;
    }
    else {
        next();
    }
}

app.get('/login', (req,res) => {
    res.render('login', {name: req.session.username, nav: nav, currentURL: urlencoded.parse(req.url).pathname});
});

app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect('/');
});


app.get('/createUser', (req,res) => {
    res.render('createUser', {nav: nav, currentURL: urlencoded.parse(req.url).pathname});
});


app.post('/submitUser', async (req,res) => {
    const { username, email, password } = req.body;

    if (!username) {
      return res.render('invalidField', {vowel: '', field: 'username', nav: nav, currentURL: urlencoded.parse(req.url).pathname});
    }
  
    if (!email) {
        return res.render('invalidField', {vowel: 'n', field: 'email', nav: nav, currentURL: urlencoded.parse(req.url).pathname});
    }
  
    if (!password) {
        return res.render('invalidField', {vowel: '', field: 'password', nav: nav, currentURL: urlencoded.parse(req.url).pathname});
    }

	const schema = Joi.object(
		{
			username: Joi.string().max(20).required().alphanum(),
            email: Joi.string().max(20).required(),
			password: Joi.string().max(20).required()
		});
	
	const validationResult = schema.validate({username, email, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/createUser");
	   return;
   }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({username: username, email: email, password: hashedPassword, user_type: "user"});
	console.log("Inserted user");
    
    res.redirect('/loggedin');
});

app.post('/loggingin', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;


	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({email: email}).project({username: 1, email: 1, password: 1, user_type: 1, _id: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
		return res.render('invalidCombo', {nav: nav, currentURL: urlencoded.parse(req.url).pathname});
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.email = email;
        req.session.username = result[0].username;
        req.session.user_type = result[0].user_type;
		req.session.cookie.maxAge = expireTime;
		res.redirect('/loggedin');
		return;
	}
	else {
		console.log("incorrect password");
		return res.render('invalidCombo', {nav: nav, currentURL: urlencoded.parse(req.url).pathname});
	}
});

app.use('/loggedin', sessionValidation);
app.get('/loggedin', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }

    res.render('loggedIn', {username: req.session.username, image1: images[0], image2: images[1], image3: images[2], name: req.session.username, nav: nav, currentURL: urlencoded.parse(req.url).pathname});
});



app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
    const result = await userCollection.find().toArray();
    res.render('users', {users: result, nav: nav, currentURL: urlencoded.parse(req.url).pathname});
});


app.get('/changeUser/:type/:username', sessionValidation, adminAuthorization, async (req, res) => {
    const username = req.params.username;
    const type = req.params.type;

    const result = await userCollection.findOne({ username });
    await userCollection.updateOne({ username }, { $set: { user_type: type } });

    res.redirect('/admin');
});

app.use(express.static(__dirname + "/public"));

app.use('/', mainPageLogIn);

app.get("*", (req,res) => {
	res.status(404);
	res.render('404', {nav: nav, currentURL: urlencoded.parse(req.url).pathname});
})

module.exports = app;

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 
