const session = require("express-session");
const bcrypt = require("bcrypt");
const ObjectId = require("mongodb").ObjectId;
const helper = require("./helper.js");
const saltRounds = 12;

module.exports = function(app, db) {
  app.use(
    session({
      secret: process.env.SECRET_SESSION_KEY,
      resave: true,
      saveUninitialized: true
    })
  );

  
  app.get("/", function(request, response) {
    if (logged_in(request.session.user_id)) {
      response.redirect("/profile");
    }
    response.render(`${__dirname}/views/index.ejs`);
  });
  
  
  app
    .route("/register")
    .get((req, res) => {
      if (logged_in(req.session.user_id)) {
        res.redirect("/profile");
      }
      res.sendFile(`${__dirname}/views/register.html`);
    })
    .post((req, res) => {
      if (logged_in(req.session.user_id)) {
        res.redirect("/profile");
      }
      const email = helper.cleanseString(req.body.email);
      const password = req.body.password;

      db.collection("users").findOne({ email: email }, (err, result) => {
        if (err) {
          res.send("/register Post Error(findOne via email): " + err + ".");
        } else if (result) {
          res.send("This email is already taken => " + email);
        } else {
          bcrypt.genSalt(saltRounds, function(fail, salt) {
            bcrypt.hash(password, salt, function(fail, hash) {
              if (fail) {
                res.send(fail.message);
              } else {
                db.collection("users").insertOne(
                  {
                    _id: new ObjectId(),
                    email: email,
                    password_hash: hash,
                    received_posts: [],
                    sended_posts: []
                  },
                  (insert_error, new_el) => {
                    if (insert_error) {
                      res.send(insert_error.message);
                    } else {
                      req.session.user_id = new_el.ops[0]._id;
                      res.redirect("/profile");
                    }
                  }
                );
              }
            });
          });
        }
      });
    });
  
  
  app.post("/login", (req, res) => {
    if (logged_in(req.session.user_id)) {
      res.redirect("/profile");
    }
    const email = helper.cleanseString(req.body.email);
    const password = req.body.password;

    db.collection("users").findOne({ email: email }, (err, result) => {
      if (err) {
        res.send("/login Post Error(findOne via email): " + err + ".");
      } else if (result) {
        const hash = result.password_hash;
        bcrypt.compare(password, hash, function(fail, outcome) {
          if (fail) {
            res.send(fail.message);
          } else {
            if (outcome) {
              req.session.user_id = result._id;
              res.redirect("/profile");
            } else {
              res.send("Wrong email or password.");
            }
          }
        });
      } else {
        res.send("Wrong email or password inputed.");
      }
    });
  });
  
  
  app.get("/logout", (req, res) => {
    req.session.user_id = undefined;
    res.redirect("/");
  });
  

  app.get("/profile", (req, res) => {
    const id = req.session.user_id;
    if (!logged_in(id)) {
      res.redirect("/");
    }

    db.collection("users").findOne({ _id: ObjectId(id) }, (err, result) => {
      if (err) {
        res.send(err.message);
      } else if (result) {
        res.render(`${__dirname}/views/profile.ejs`, {
          user_email: result.email
        });
      }
    });
  });
  
  
  
  
  /*                                     helper methods depends on app and db added here                                    */
  const logged_in = function(id) {
    if (typeof id === "undefined") {
      return false;
    }

    return true;
  };
  /*                                     helper methods depends on app and db added here                                    */
};
