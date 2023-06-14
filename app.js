import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import cookieParser from 'cookie-parser';
import logger from 'morgan';
import fs from 'fs';
import multer from 'multer';
const upload = multer({ dest: "uploads/"});
import {exec} from "child_process";

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

    // SHOWCASE:
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

    // SHOWCASE:
    // Here is a timing attack hidden, since we are not using a
    // constant time comparison
    if(hashedPassword !== user.password) {
        return res.status(401).send("invalid login");
    }

    // SHOWCASE:
    // Just a simple Cookie containing the userId is bad.
    // This should be a digitally signed cookie to detect tampering
    // on the client side.
    res.cookie("loggedInUserId", user.id);

    return res.redirect("/");
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

    // SHOWCASE:
    // To support non ascii filenames we decode URI escape sequences
    // with catastrophic consequences. This way it is easy to inject HTML
    // via the client provided `originalname`
    const originalFileName = decodeURIComponent(uploadedFile.originalname);

    const statement = db.prepare("INSERT INTO uploads (user_id, storageLocation, originalFileName, size, mimeType) VALUES (?, ?, ?, ?, ?)");

    // SHOWCASE:
    // 'uploadedFile.originalname' is a "hidden" user input that is not validated/escaped!
    // An attacker may choose to send any arbitrary string alongside the uploaded file.
    //
    // See: https://curl.se/docs/manpage.html#-F
    //      You can also explicitly change the name field of a file upload part by setting filename=, like this:
    //      curl -F "file=@localfile;filename=nameinpost" example.com
    statement.run(user.id, uploadedFile.path, originalFileName, uploadedFile.size, uploadedFile.mimetype);

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

app.delete("/api/upload/:uploadId", (req, res) => {
    const { uploadId } = req.params;

    if(uploadId === undefined) {
        return res.send(404).send("missing upload id");
    }

    const user = getUserFromSessionCookie(req);

    if(user === undefined) {
        return res.status(401).send("login required"); 
    }

    // SHOWCASE:
    // Well, we could check, if the upload the user would like to delete
    // actually belongs to this user...but that would be way to complex... ;)
    // This any user can delete any upload as long as he knows the id
    const statement = db.prepare("DELETE FROM uploads WHERE id = ?");  // AND user_id = ?
    statement.run(uploadId);

    return res.status(200).send("upload deleted");
});

app.get("/api/uploads", (req, res) => {
    const user = getUserFromSessionCookie(req);

    if(user === undefined) {
        return res.status(401).send("login required"); 
    }

    const statement = db.prepare("SELECT * FROM uploads WHERE user_id = ?");
    const uploads = statement.all(user.id);

    return res.send(uploads);
});

app.get("/api/admin/cleanup", (req, res) => {
    const user = getUserFromSessionCookie(req);

    if(user === undefined) {
        return res.status(401).send("login required");
    }

    if(!user.isAdmin) {
        return res.status(401).send("only admins may do this");
    }

    db.prepare("DELETE FROM uploads").run();

    const files = fs.readdirSync("uploads/");
    files.forEach(filename => fs.unlinkSync("uploads/" + filename));

    return res.send("all uploads deleted");
});

app.get("/list-directory", (req, res) => {
    const directory = req.query.directory;

    // SHOWCASE
    // DANGER DANGER DANGER DANGER DANGER DANGER
    // The exec command starts a new shell and executes the command in this shell.
    // A part of the command is user-controlled, therefore it is easy to launch a remote shell
    // (or any other arbitrary command on the server)
    // DO NOT DO THIS!
    exec("ls -latr " + directory, { shell: "/bin/bash" }, (error, stdout, stderr) => {
        if(error || stderr) {
            return res.send("failed to start process");
        }

        res.send(stdout);
    });
});

function hashPassword(password) {
    // SHOWCASE:
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
