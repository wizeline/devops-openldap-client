#! /usr/bin/env node

require('dotenv').config({ path: __dirname + '/.env' });

const opn = require('opn');
const request = require('request');
const crypto = require('crypto');
const Q = require('q');
const http = require('http');
const co = require('co');
const fs = require('fs');
const os = require('os');
const prompt = require('co-prompt');

const defaultPem = 'id_rsa.pub';
const PORT = process.env.APP_PORT || 3000;
const LDAP_SERVER = process.env.LDAP_SERVER || 'http://httpbin.org/post';
const promise = Q.defer();

function base64url(b) {
  return b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function sendPem(idToken) {
  if (!idToken) {
    console.log('ERROR: Token not found');
    process.exit(-1);
  }

  co(function *() {
    const defaultPemFlag = yield prompt('Which pem do you want to use[' + defaultPem + ']?');
    const pubFile = os.homedir() + '/.ssh/' + (defaultPemFlag || defaultPem);
    try {
      const pubFileContent = fs.readFileSync(pubFile, 'utf8');
      return pubFileContent;
    } catch(e) {
      return null;
    }
  })
  .then(function(pemContent) {
    if (!pemContent) process.exit(-1);

    const data = { jwt: idToken, sshPublicKey: pemContent };
    const options = { url: LDAP_SERVER, json: data, headers: { 'Content-Type': 'application/json' } };
    request
      .post(options, function(err, response, body) {
        if (err) {
          console.log('ERROR: ' + err);
          process.exit(-1);
        }

        console.log(body);
        process.exit(0);
      });
  });
}

http.createServer(function (req, res) {
  var matches = req.url.match(/code=([^&]+).*$/);
  if (matches instanceof Array && matches.length >= 2) {
    promise.resolve(matches[1]);
    res.write('Success, close the tab and go back to the terminal');
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
opn(authorize_url)
  .catch(function(err) {
    console.log('Error opening ' + authorize_url);
  });

promise.promise
  .then(function(code) {
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
        if (err) {
          console.log('ERROR: ' + err);
          process.exit(-1);
        }

        if (!response) {
          console.log('ERROR: Response not found');
          process.exit(-1);
        }

        if (response.statusCode !== 200) {
          console.log('ERROR: Response code is ' + response.statusCode);
          process.exit(-1);
        }

        sendPem(body.id_token);
      }
    );
  })
  .fail(function(err) {
    console.log(err);
    process.exit(-1);
  });
