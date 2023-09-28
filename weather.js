var express = require('express');
var app = express();

app.use(express.static('public'));

const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore, Filter } = require('firebase-admin/firestore');
var serviceAccount = require("./key.json");

initializeApp({
    credential: cert(serviceAccount)
});

const db = getFirestore();

app.get('/signup', function (req, res) {
    res.sendFile(__dirname + "/public/" + "signup.html");
});

app.get('/login', function (req, res) {
    res.sendFile(__dirname + "/public/" + "login.html");
});

app.get('/loginup', function (req, res) {
    res.sendFile(__dirname + "/public/" + "weather.html");
});

// Function to hash a password
var crypto = require('crypto'); // Import the crypto module

function hashPassword(password) {
    const hash = crypto.pbkdf2Sync(password, crypto.randomBytes(16), 10000, 64, 'sha512').toString('hex');
    return hash;
}

// Function to verify a password
function verifyPassword(password, storedHash) {
    const hash = crypto.pbkdf2Sync(password, Buffer.from(storedHash, 'hex'), 10000, 64, 'sha512').toString('hex');
    return hash === storedHash;
}

app.get('/signin', function (req, res) {
    db.collection('userDemo')
        .where(
            Filter.or(
                Filter.where("Email", "==", req.query.Email),
                Filter.where("userName", "==", req.query.Fullname)
            )
        )
        .get()
        .then((docs) => {
            if (docs.size > 0) {
                res.send("This is an existing account");
            } else {
                // Convert req.query.Password to a string
                const password = req.query.Password.toString();

                // Hash the password before storing it
                const hashedPassword = hashPassword(password);

                db.collection("userDemo")
                    .add({
                        userName: req.query.Fullname,
                        Email: req.query.Email,
                        PasswordHash: hashedPassword, // Store the hashed password only
                    })
                    .then(() => {
                        res.sendFile(__dirname + "/public/login.html");
                    })
                    .catch(() => {
                        res.send("Something went wrong");
                    });
            }
        });
});

app.get("/loginup", function (req, res) {
    db.collection('userDemo')
        .where("Email", "==", req.query.Email)
        .get()
        .then((docs) => {
            if (docs.size > 0) {
                const storedHash = docs.docs[0].data().PasswordHash;

                // Verify the hashed password
                if (verifyPassword(req.query.Password, storedHash)) {
                    res.send("Successful"); // Passwords match
                } else {
                    res.send("Failed"); // Passwords do not match
                }
            } else {
                res.send("Failed"); // User not found
            }
        })
        .catch(() => {
            res.send("Something went wrong");
        });
});

app.get("/login", function (req, res) {
    res.sendFile(__dirname + "/public/login.html");
});

app.listen(3000);
