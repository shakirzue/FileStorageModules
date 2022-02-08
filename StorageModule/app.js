var express = require('express');
const fileUpload = require('express-fileupload');
const config = require('./config/config');
const jwt = require('jsonwebtoken');
const bodyparser = require('body-parser');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser')
var sql = require("mssql");
var cors = require('cors')
require('dotenv').config();
const fileUploader = require('./services/file-uploader-service');

var app = express();
app.use(bodyParser.urlencoded({ extended: false }));

// parse application/json
app.use(bodyParser.json());
// parse various different custom JSON types as JSON
app.use(bodyParser.json({ type: 'application/*+json' }))

// parse some custom thing into a Buffer
app.use(bodyParser.raw({ type: 'application/vnd.custom-type' }))

// parse an HTML body into a string
app.use(bodyParser.text({ type: 'text/html' }))

app.use(cors({
    origin: process.env.CLIENT_URL,
    optionsSuccessStatus: 200, // some legacy browsers (IE11, various SmartTVs) choke on 204
    methods: ['GET', 'POST', 'DELETE', 'UPDATE', 'PUT', 'PATCH']
}));

app.use(cookieParser());
app.use(fileUpload());

var request;
app.get('/', cors(), function (req, res) {

    res.send("Welcome to Zue storage module");
});

app.post('/login', function (req, res) {
    var dbpassword;
    var dbprofileid;
    var isPasswordMatched = false;

    // connect to your database
    sql.connect(config, function (err) {
        if (err) console.log(err);
        // create Request object
        request = new sql.Request();

        // query to the database and get the records
        request.input('email', sql.NVarChar, req.body.email)
        request.query('select * from dbo.adminprofile WHERE email = @email', function (err, result) {

            if (err) console.log(err)

            // send records as a response           
            if (result.recordset.length > 0) {
                dbpassword = result.recordset[0].Password;
                dbprofileid = result.recordset[0].Id;
            }

            if (req.body.password == dbpassword) {
                console.log('password has matched');
                isPasswordMatched = true;
            }
            else {
                console.log('password has not matched');
                isPasswordMatched = false;
            }

            if (isPasswordMatched === true) {

                const token = jwt.sign({ user_id: dbprofileid }, process.env.SECRET,
                    {
                        expiresIn: "2h"
                    }
                );
                request.input('token', sql.NVarChar, token);
                request.input('useremail', sql.NVarChar, req.body.email);
                request.query('Update [dbo].[adminprofile] SET Token = @token where email = @useremail', (err, result) => {
                    if (err) console.log(err);

                    res.cookie('auth', token, { expires: new Date(Date.now() + 1000 * 60), httpOnly: true });
                    res.cookie('email', req.body.email, { expires: new Date(Date.now() + 1000 * 60), httpOnly: true });
                    // res.send('Cookie is set');
                    return res.json({ success: true, message: "user logged in successfully.", auth: token, email: req.body.email });;
                });
            }
            else {
                return res.json({ isAuth: false, message: "password doesn't match" });
            }
        });
    });
});

function getToken(email, token, res, cb) {
    sql.connect(config, function (err) {
        if (err) console.log(err);
        // create Request object
        request = new sql.Request();
        // query to the database and get the records
        request.input('email', sql.NVarChar, email);
        request.input('Token', sql.NVarChar, token)
        request.query('select token from dbo.adminprofile WHERE Email = @email AND Token = @token', function (err, result) {
            if (err) console.log(err);
            // send records as a response           
            if (result.recordset.length > 0) {
                res.send('already logged in');
                cb(true);
            }
            else {
                res.send('please login again');
                cb(false);
            }

        });
    })

}
app.post("/blobupload", function (req, res) {
    console.log(req.body.folderpath);
    getToken(req.body.email, req.body.auth, res, (result) => {
        console.log(result)
        if (true) {
            fileUploader.blobUpload(req, res, req.body.folderpath);
        }
    });
});
app.post("/fileupload", function (req, res) {
    fileUploader.reportUpload(req, res);

});

app.get("/logout", (req, res) => {
    // clear the cookie
    res.clearCookie("auth");
    res.clearCookie("email");
    // redirect to login
    return res.redirect("/login");
});

var server = app.listen(process.env.SERVER_RUN_PORT, function () {
    console.log('Server is running..');
});