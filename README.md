# express-jwt-authentication

`express-jwt-authentication` is a very simple and lightweight library written in **TypeScript** that provides a ready-to-use middleware to quickly and securely manage authentication using **JWT** ([Json Web Token](https://jwt.io/)) on any [Express](https://expressjs.com/it/) application. 

This module depends on [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken), which is used for token verification and payload extraction. 

## Installation

```shell
npm install express-jwt-authentication
```
## Basic usage

A very simple and common use of middleware:

```javascript
const expressJwtAuthentication = require("express-jwt-authentication");

const options = { 
    secret: "WN4G0PXBR0F7MSMPQ2JQJ22S3GRSD69A963HG6RBUFFF5YSLYB8ZK365H7MXGI8E", 
    algorithm: "HS256" 
};

app.get(
    "/api/protected",
    expressJwtAuthentication(options),
    (req, res, next) => res.json(req.user)
);
```

In this example, to access the `/api/protected` endpoint, the user will first need to authenticate through the middleware using a valid **JWT**. 

`expressJwtAuthentication` requires an object to be passed as a parameter containing the options to use. In this specific case, only the not optional settings are provided, which respectively are the `secret` and the `algorithm` used for the token encryption.

By default, the middleware will try to retrieve the **JWT** from the **HTTP** request's **Authorization** header:

```bash
curl http://localhost/api/protected -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2MzM5NzAzNDh9.DvIzqlKXMQQjmB5zPlKLgs83VeHo6nR-ISIO2wYyGV0"
```

The payload of the authenticated **JWT** will be stored in the `req.user` property, granting easy access to any valid claim:

```javascript
console.log(req.user.sub);
```

If the **Authorization** header is not provided or its content does not comply with the standard, the middleware will throw a `MissingAuthorizationHeaderError` or an `InvalidAuthorizationHeaderError` using `next()`.

## Allow guest authentication

It may be necessary to grant access to a secure endpoint even if no **JWT** is used. In this way the middleware will continue to identify authenticated users but still provide access to guests:

```javascript
expressJwtAuthentication({ 
    [...]
    allow_guests: true 
});
```

In the case of a guest authentication, the middleware will not change the value assigned to `req.user`, which will remain `undefined`.

## Check claims before authentication

The middleware allows restrictions on claims and their respective acceptable values to be set. These requirements must be met for authentication with **JWT** to be successful:

```javascript
expressJwtAuthentication({ 
    [...]
    required_claims: {
        "role": [ "moderator", "administrator" ],
        "iss": [ "http://localhost:8080" ],
        "type": [ "access-token" ]
    } 
});
```

In the example above, the authentication will only succeed if the **JWT** used will contain all three specified claims set to one of their respective acceptable values as indicated in the options. 

Otherwise, the middleware will throw a `ClaimNotAllowedError` using `next()`.

## Custom token retrieval

By default, the **JWT** is implicitly retrieved from the **Authorization** header. It is possible, however, to define a `retrieveJwt()` method that manually and explicitly returns the token to use for the authentication:

```javascript
expressJwtAuthentication({ 
    [...]
    retrieveJwt: (req, res, next) => {
        if(req.query)
            return req.query.token;

        return null;
    }
});
```

The method behaves like any other **Express** middleware. Therefore, the typical `req`, `res` and `next` parameters provided by the framework can be used to handle the token retrival.

It must return a `string` containing the **JWT** to use, or `null` if none were provided within the **HTTP** request.

If no token is provided, the middleware will throw an `InvalidTokenError` using `next()`.

## Handle revoked tokens

It is possible to perform a manual check on the tokens accepted by the middleware to verify that they have not been previously revoked. To do this, simply define the appropriate `isRevoked()` method within the options:

```javascript
expressJwtAuthentication({ 
    [...]
    isRevoked: (payload) => {
        const 
            iss = payload.iss,
            jti = payload.jti;

        const token = [ iss, jti ];

        return revokedTokens.includes(token);
    }
});
```

The payload of the **JWT** used for authentication is passed as a parameter to the method, which must return a boolean value corresponding to the result of the check. `true` if the token has been revoked, `false` if the token is still valid.

If the used token is revoked, the middleware will throw a `RevokedTokenError` using `next()`.

## Environment variables

It is possible to globally define the `secret` and the `algorithm` to use to decode the tokens. This way, they won't have to be specified every time the middleware is invoked. To do this, just assign the desired values to the environment variables `EXPRESS_JWT_AUTHENTICATION_SECRET` and `EXPRESS_JWT_AUTHENTICATION_ALGORITHM`:

```shell
EXPRESS_JWT_AUTHENTICATION_SECRET=[SECRET] EXPRESS_JWT_AUTHENTICATION_ALGORITHM=[ALGORITHM] node app.js
```

If the application includes [dotenv](https://github.com/motdotla/dotenv) or a similar library, the environment variables can also be set through a `.env` file:

```
EXPRESS_JWT_AUTHENTICATION_SECRET=WN4G0PXBR0F7MSMPQ2JQJ22S3GRSD69A963HG6RBUFFF5YSLYB8ZK365H7MXGI8E
EXPRESS_JWT_AUTHENTICATION_ALGORITHM=HS256
```

In this way, the middleware can be used like this:

```javascript
app.get(
    "/api/protected",
    expressJwtAuthentication({}),
    (req, res, next) => res.json(req.user)
);
```

## Error handling

A very simple and generic error handler can be implemented overriding the Express's default one:

```javascript
app.use(function(err, req, res, next) {
    switch(err.name) {
        case "JsonWebTokenError":
        case "NotBeforeError":
        case "TokenExpiredError":

        case "MissingAuthorizationHeaderError":
        case "InvalidAuthorizationHeaderError":
        case "MissingTokenError":
        case "RevokedTokenError":
        case "ClaimNotAllowedError":
            res.status(401).send(err.message);
            break;
    }
});
```
The first three cases are used to handle errors thrown directly by `jsonwebtoken`, in case something wrong happens during the verification of a **JWT**. 

The following five are implemented and thrown by the middleware itself when needed. 

Each error is passed as a parameter to `next()` to be handled later.

## Supported encryption algorithms

Currently, this module supports most of the symmetric and asymmetric encryption algorithms supported by `jsonwebtoken` itself. 

Here is a list updated to the version of the library in use by the middleware containing all the available strategies:

Algorithm | Digital Signature or MAC Algorithm
----------------|----------------------------
HS256 | HMAC using SHA-256 hash algorithm
HS384 | HMAC using SHA-384 hash algorithm
HS512 | HMAC using SHA-512 hash algorithm
RS256 | RSASSA-PKCS1-v1_5 using SHA-256 hash algorithm
RS384 | RSASSA-PKCS1-v1_5 using SHA-384 hash algorithm
RS512 | RSASSA-PKCS1-v1_5 using SHA-512 hash algorithm
ES256 | ECDSA using P-256 curve and SHA-256 hash algorithm
ES384 | ECDSA using P-384 curve and SHA-384 hash algorithm
ES512 | ECDSA using P-521 curve and SHA-512 hash algorithm
none | No digital signature or MAC value included

## Building from source code

Install all required `dependencies` and `devDependencies`:

```shell
npm install
```

Then, build the project:

```shell
npm run build
```

## Testing

The unit tests provided are written in [Jasmine](https://jasmine.github.io/). They can be performed using:

```shell
npm test
```

## License 

This project is released under the [**MIT License**](https://opensource.org/licenses/MIT):

```
MIT License

Copyright (c) 2021 Davi0k

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```