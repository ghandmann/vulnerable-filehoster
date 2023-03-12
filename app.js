import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import cookieParser from 'cookie-parser';
import logger from 'morgan';
import fs from 'fs';
import multer from 'multer';
const upload = multer({ dest: "uploads/"});

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

app.post("/api/upload", upload.single("file"), (req, res) => {
    const uploadedFile = req.file;

    const user = getUserFromSessionCookie(req);

    if(user === undefined) {
        return res.status(401).send("only logged in users can upload files");
    }

    const statement = db.prepare("INSERT INTO uploads (user_id, storageLocation, originalFileName, size, mimeType) VALUES (?, ?, ?, ?, ?)");

    // 'uploadedFile.originalname' is a "hidden" user input that is not validated/escaped!
    // An attacker may choose to send any arbitrary string alongside the uploaded file.
    //
    // See: https://curl.se/docs/manpage.html#-F
    //      You can also explicitly change the name field of a file upload part by setting filename=, like this:
    //      curl -F "file=@localfile;filename=nameinpost" example.com
    statement.run(user.id, uploadedFile.path, uploadedFile.originalname, uploadedFile.size, uploadedFile.mimetype);

    return res.send("file upload successfull");
});

app.get("/api/download/:uploadId", (req, res) => {
    const { uploadId } = req.params;

    if(uploadId === undefined) {
        return res.send(404).send("missing upload id");
    }

    const statement = db.prepare("SELECT * FROM uploads WHERE id = ?");
    const fileUpload = statement.get(uploadId);

    if(fileUpload === undefined) {
        return res.send(404).send("invalid upload id");
    }

    const fileBytes = fs.readFileSync(fileUpload.storageLocation);

    res.type(fileUpload.mimeType).send(fileBytes);
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

    const statement = db.prepare("SELECT * FROM users WHERE id = ?");
    const user = statement.get(loggedInUserId);

    return user;
}

export default app;
