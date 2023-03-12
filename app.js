import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import cookieParser from 'cookie-parser';
import logger from 'morgan';

import indexRouter from './routes/index.js';
import usersRouter from './routes/users.js';

const {
    createHash,
  } = await import('node:crypto');

import db from "./db.js"


const __dirname = path.dirname(fileURLToPath(import.meta.url));

var app = express();

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', indexRouter);
app.use('/users', usersRouter);

app.post("/api/login", (req, res) => {
    const { email, password } = req.body;

    // The next line contains a serious SQL injection vulnerarble.
    // Although it seems like there are prepared statments used here, 
    // in reality which just concat user input (email) to the raw SQL.
    // The fixed version would look like this:
    //      const statement = db.prepare("SELECT * FROM users WHERE email = ?);
    // See: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
    const statement = db.prepare("SELECT * FROM users WHERE email = '" + email + "'");

    // TODO is this still injectable for statement.get() and a "LIMIT 1" select?
    const result = statement.all();

    if(result.length == 0) {
        return res.status(401).send("invalid login");
    }
    
    const hashedPassword = hashPassword(password);
    
    const user = result[0];

    // Here is a timing attack hidden, since we are not using a
    // constant time comparison
    if(hashedPassword !== user.password) {
        return res.status(401).send("invalid login");
    }

    // Just a simple Cookie containing the userId is bad.
    // This should be a digitally signed cookie to detect tampering
    // on the client side.
    res.cookie("loggedInUserId", userId);

    return res.send("login successfull");
});

app.post("/api/register", (req, res) => {
    const { email, password } = req.body;

    const userExists = db.prepare("SELECT * FROM users WHERE email = ?").get(email) !== undefined;
    if(userExists) {
        return res.status(409).send("user with email already exists");
    }

    const passwordHash = hashPassword(password);

    const insertStatement = db.prepare("INSERT INTO users (email, password, isAdmin) VALUES (?, ?, false)");
    insertStatement.run(email, passwordHash);

    return res.send("user registered");
});

app.get("/api/profile", (req, res) => {
    const user = getUserFromSessionCookie(req);

    if(user === undefined) {
        return res.status(404).send("unknown user id");
    }

    return res.send({ id: user.id, email: user.email, isAdmin: user.isAdmin });
});

function hashPassword(password) {
    // MD5 is bad. Really bad. Never ever hash passwords with MD5!
    // And allways salt your hashes!
    // See https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
    const md5Hash = createHash("md5");
    const hashedPassword = md5Hash.update(password + "").digest("hex");

    return hashedPassword;
}

function getUserFromSessionCookie(req) {
    const loggedInUserId = req.cookies.loggedInUserId;

    if(loggedInUserId === undefined) {
        return res.status(401).send("unauthorized");
    }

    const statement = db.prepare("SELECT * FROM users WHERE id = ?");
    const user = statement.get(loggedInUserId);

    return user;
}

export default app;
