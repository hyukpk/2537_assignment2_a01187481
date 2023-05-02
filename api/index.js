
// require("../utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const saltRounds = 12;
const app = express();


// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }));

// parse application/json
app.use(bodyParser.json());


const port = process.env.PORT || 3000;


const Joi = require("joi");


const expireTime = 24 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

const client = require("../databaseConnection");

const userCollection = client.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));
app.use(express.static(__dirname + "/../public"));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
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

app.get('/', (req,res) => {
    var html = `
    <form action='/createUser'>
        <button>Sign Up</button>
    </form>    
    <form action='/login'>
        <button>Log In</button>
    </form>
    `;
    res.send(html);
});

app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.post('/submitEmail', (req,res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.send("Thanks for subscribing with your email: "+email);
    }
});


app.get('/createUser', (req,res) => {
    var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='username'>
    <input name='email' type='email' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});


app.get('/login', (req,res) => {

    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='email' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/submitUser', async (req,res) => {
    const { username, email, password } = req.body;

    if (!username) {
      return res.send('Please provide a username. <a href="/createUser">Try Again</a>');
    }
  
    if (!email) {
      return res.send('Please provide an email address. <a href="/createUser">Try Again</a>');
    }
  
    if (!password) {
      return res.send('Please provide a password. <a href="/createUser">Try Again</a>');
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
	
	await userCollection.insertOne({username: username, email: email, password: hashedPassword});
	console.log("Inserted user");

    req.session.authenticated = true;
    req.session.email = email;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;
    
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

	const result = await userCollection.find({email: email}).project({username: 1, email: 1, password: 1, _id: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
		return res.send('Invalid email/password combination. <a href="/login">Try Again</a>');
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.email = email;
        req.session.username = result[0].username;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/loggedin');
		return;
	}
	else {
		console.log("incorrect password");
		return res.send('Invalid email/password combination. <a href="/login">Try Again</a>');
	}
});

app.get('/loggedin', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    function getRandomInt(max) {
        return Math.floor(Math.random() * max);
      }
    if (getRandomInt(3) == 0) {
        var imageName = "1.png";
    }
    else if (getRandomInt(3) == 1) {
        imageName = "2.png";
    }
    else {
        imageName = "3.png";
    }
    var html = `<h1>Hello , ` + req.session.username + `!</h1>` 
    + `<br>` + '<img src="${imageName}" alt="Random image" style="width: 200px; height: 200px;">'
    + `<br>`
    + `<form action='/logout' method='get'>
            <button>Log out</button>
        </form>`;
    res.send(html);
});

app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect('/');
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.send('<img src="/error.jpg" style="width: 250px;"></img><p>404 - Could not find the page you were looking for</p>');
})

module.exports = app;

// app.listen(port, () => {
// 	console.log("Node application listening on port "+port);
// }); 
