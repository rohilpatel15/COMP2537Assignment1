require('dotenv').config();
const express = require('express');
const session = require('express-session');
const Mongostore = require('connect-mongo');
const bcrypt = require('bcrypt');

const saltRounds = 12;

const Joi = require('joi');

const app = express();

const port = process.env.PORT || 3020;

const timeExpired = 1 * 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

var {database} = require('./databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = Mongostore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}?retryWrites=true&w=majority`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveOnInitialized: false,
    resave: true,
}
));

app.get('/', (req, res) => {
    var html = '';
    if (req.session.username) {
        html += `
            <h1>Hello, ${req.session.username}!</h1>
            <p>You are currently logged in.</p>
            <p><a href="/members">Go to members page</a></p>
            <form action="/logout" method="post">
                <button type="submit">Log Out</button>
            </form>
        `;
    } else {
        html += `
            <h1>Welcome to My Site</h1>
            <p>Please sign up or log in:</p>
                <a href="/createUser">Sign up</a>
                <a href="/login">Log in</a>
        `;
    }
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

	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/createUser', (req,res) => {
    var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='username'>
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
    <input name='username' type='text' placeholder='username'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/submitUser', async (req,res) => {
    var username = req.body.username;
    var password = req.body.password;

	const schema = Joi.object(
		{
			username: Joi.string().alphanum().max(20).required(),
			password: Joi.string().max(20).required()
		});
	
	const validationResult = schema.validate({username, password});

	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/createUser");
	   return;
   }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({username: username, password: hashedPassword});
	console.log("Inserted user");

    req.session.username = username;

    res.redirect('/members');
});

app.get('/members', (req, res) => {
    if (!req.session.username) {
        res.redirect('/login');
    }
    var html = `
        <h1>Welcome, ${req.session.username}!</h1>
        <p>You are now a member of our site.</p>
		<form action="/logout" method="post">
            <button type="submit">Log Out</button>
        </form>
    `;
    res.send(html);
});


app.post('/loggingin', async (req,res) => {
    var username = req.body.username;
    var password = req.body.password;

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	if (result.length != 1) {
		console.log("user not found");
		res.redirect("/login");
		return;
	}

	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");

		req.session.username = username;

		res.redirect('/members');
		return;
	}
	else {
		console.log("incorrect password");
		res.redirect("/login");
		return;
	}
});

app.get('/loggedin', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    var html = `
    You are logged in!
    `;
    res.send(html);
});

app.post('/logout', (req, res) => {
    req.session.destroy(() => {
        mongoStore.destroy(req.sessionID, (err) => {
            if (err) {
                console.log(err);
            }
            res.redirect('/');
        });
    });
});



app.get('/cat/:id', (req,res) => {

    var cat = req.params.id;

    if (cat == 1) {
        res.send("Fluffy: <img src='/fluffy.gif' style='width:250px;'>");
    }
    else if (cat == 2) {
        res.send("Socks: <img src='/socks.gif' style='width:250px;'>");
    }
    else {
        res.send("Invalid cat id: "+cat);
    }
});


app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 