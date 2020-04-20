const express = require("express");
const mysql = require("mysql");
const bodyParser = require("body-parser");
const cors = require("cors");
const { genSaltSync, hashSync, compareSync } = require("bcrypt");
const { sign } = require("jsonwebtoken");

const { checkToken } = require("./token_validation");

require("dotenv").config();

const app = express();
app.use([cors(), bodyParser()]);

const db_conn = mysql.createConnection({
  port: process.env.DB_PORT,
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.MYSQL_DB,
});

db_conn.connect((err) => {
  if (err) throw err;

  console.log("Connected to MySQL 'track_it' database!");

  app.listen(process.env.APP_PORT, function () {
    console.log("Server listening on port 3000!");
  });
});

/*
    USERS ROUTES
*/

app.post("/users/sign_up", (req, res) => {
  const salt = genSaltSync(10);

  const body = req.body;
  body.password = hashSync(body.password, salt);

  const sql = "INSERT INTO users (email, password) VALUES (?, ?)";

  db_conn.query(sql, [body.email, body.password], function (err, result) {
    if (err) {
      res.status(500).json(err);
    } else {
      res.status(200).json(result);
    }
  });
});

app.post("/users/sign_in", (req, res) => {
  const body = req.body;
  const sql = "SELECT * FROM users WHERE email = ?";

  db_conn.query(sql, [body.email], function (err, result) {
    if (err) {
      res.status(500).json(err);
    } else {
      if (result.length == 0) {
        res.status(404).json({ message: "Invalid email or password" });
      } else {
        const user = result[0];
        const success = compareSync(body.password, user.password);

        if (success) {
          user.password = undefined;

          const jsontoken = sign({ result: user }, process.env.APP_SECRET, {
            expiresIn: "2w",
          });

          return res.status(200).json({
            user_id: user.id,
            email: user.email,
            token: jsontoken,
          });
        } else {
          res.status(404).json({ message: "Invalid email or password" });
        }
      }
    }
  });
});

app.get("/test", checkToken, (req, res) => {
  res.status(200).json({ message: "Ok!" });
});
