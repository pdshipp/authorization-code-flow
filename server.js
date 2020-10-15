const express = require("express");
const axios = require("axios");
const querystring = require("querystring");
const keys = require("./credentials");
const stateGen = require("./utils");

const redirect_uri = "http://localhost:8888/auth/callback";

const app = express();
// generate state to prevent CSRF attack
const state = stateGen.randomString(10);

// Request authorization code directing user to OAuth authorization page
app.get("/login", function (req, res) {
  // if there is valid persmission grant, authorization screen is bypassed and member is immmediately redirected to redirect_url
  res.redirect(
    "https://www.linkedin.com/oauth/v2/authorization?" +
      querystring.stringify({
        response_type: "code",
        client_id: keys.LINKEDIN.clientID,
        scope: "r_liteprofile",
        state: state,
        redirect_uri,
      })
  );
});

// once application is approved, user taken to redirect_url with code/state arguments attached to the URL
app.get("/auth/callback", (req, res) => {
  // extraction to authorization code to exchange with LinkedIn
  const requestToken = req.query.code;
  // check state matches param generated at start
  if (req.query.state === state) {
    // Exchange of auth code for Access Token
    axios({
      method: "post",
      url: `https://www.linkedin.com/oauth/v2/accessToken?grant_type=authorization_code&code=${requestToken}&redirect_uri=${redirect_uri}&client_id=${keys.LINKEDIN.clientID}&client_secret=${keys.LINKEDIN.clientSecret}`,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    }).then((response) => {
      // use of access token to make authenticated API requests
      const accessToken = response.data.access_token;
      axios
        .get("https://api.linkedin.com/v2/me", {
          Connection: "Keep-Alive",
          headers: { Authorization: `Bearer ${accessToken}` },
        })
        .then((res) => {
          console.log(res.data);
        });
    });
  } else {
    console.log("state mismatch");
  }
});

const port = process.env.PORT || 8888;
console.log(
  `Listening on port ${port}. Go /login to initiate authentication flow.`
);

app.listen(port);
