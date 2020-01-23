const request = require('request'),
  jwt = require('jsonwebtoken'),
  jwkToPem = require('jwk-to-pem'),
  config = require('config');

module.exports = function () {
  return (req, res, next) => {
    validateToken(req)
      .then((result) => {
        req["user"] = result;
        next();
      })
      .catch((err) => {
        next(err);
      });
  };
}

const validateToken = (req) => {
  return new Promise(function (resolve, reject) {
    if (req.headers.hasOwnProperty("authorization")) {
      let token = req.headers.authorization.replace('Bearer ', '');
      token = token.replace('bearer ', '');
      request({
        url: `https://cognito-idp.${config.Cognito.region}.amazonaws.com/${config.Cognito.userpoolId}/.well-known/jwks.json`,
        json: true
      }, function (error, commonr, body) {
        if (!error && commonr.statusCode === 200) {
          pems = {};
          var keys = body['keys'];
          for (var i = 0; i < keys.length; i++) {
            //Convert each key to PEM
            var key_id = keys[i].kid;
            var modulus = keys[i].n;
            var exponent = keys[i].e;
            var key_type = keys[i].kty;
            var jwk = {
              kty: key_type,
              n: modulus,
              e: exponent
            };
            var pem = jwkToPem(jwk);
            pems[key_id] = pem;
          }
          //validate the token
          var decodedJwt = jwt.decode(token, {
            complete: true
          });

          if (!decodedJwt) {
            return reject(new Error("Invalid token. JWT decoding failed.."));
          }

          var kid = decodedJwt.header.kid;
          var pem = pems[kid];

          if (!pem) {
            return reject(new Error("Invalid token. JWT had invalid kid value."));
          }

          console.log("Token: " + token);
          console.log("Pem: " + pem);
          jwt.verify(token, pem, function (err, payload) {
            if (err) {
              console.log("Error: " + err);
              reject(new Error("Invalid token.", err));
            } else {
              payload['token'] = token;
              resolve(payload);
            }
          });
        }
        else {
          reject(new Error("Unable to fetch metadata from tokenserver."));
        }
      });
    } else {
      reject(new Error("No token found. Please supply JWT token in Authorization header.ex: Authorization: Bearer < JWT > "));
    }
  });
};