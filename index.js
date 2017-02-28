#! /usr/bin/env node

require('dotenv').load();

var opn = require('opn');
var request = require('request');
var crypto = require('crypto');
var Q = require('q');
var http = require('http');

const PORT = process.env.APP_PORT || 3000;

const promise = Q.defer();

function base64url(b) {
  return b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

http.createServer(function (req, res) {
  var matches = req.url.match(/code=([^&]+).*$/);
  if (matches instanceof Array && matches.length >= 2) {
    promise.resolve(matches[1]);
    res.write(matches[1]);
  } else {
    promise.reject('Unable to find code');
  }
  res.end();
}).listen(PORT);

var env = {
  AUTH0_CLIENT_ID: process.env.AUTH0_CLIENT_ID,
  AUTH0_URL: process.env.AUTH0_URL,
  AUTH0_CALLBACK_URL: process.env.AUTH0_CALLBACK_URL || 'http://localhost:' + PORT + '/callback',
};

//Generate the verifier, and the corresponding challenge
var verifier = base64url(crypto.randomBytes(32));
var verifier_challenge = base64url(crypto.createHash('sha256').update(verifier).digest());

var authorize_url = env.AUTH0_URL + '/authorize?response_type=code&scope=openid%20profile&' +
  'client_id=' + env.AUTH0_CLIENT_ID + '&redirect_uri=' + env.AUTH0_CALLBACK_URL +
  '&code_challenge=' + verifier_challenge + '&code_challenge_method=S256';
opn(authorize_url);

promise.promise.then(function(code) {
  request.post(env.AUTH0_URL + '/oauth/token',
    {
      json: {
        code: code,
        code_verifier: verifier,
        client_id: env.AUTH0_CLIENT_ID,
        grant_type: 'authorization_code',
        redirect_uri: env.AUTH0_CALLBACK_URL
      }
    },
    function(err, response, body){
      //TODO: do something useful with the token (in body)
      //CLI is ready to call APIs, etc.
      console.log('error:', err); // Print the error if one occurred
      console.log('statusCode:', response && response.statusCode); // Print the response status code if a response was received
      console.log('body:', body);
    }
  );
});
