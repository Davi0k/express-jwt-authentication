/* eslint-disable */

import middleware, { IOptions } from "../src"

import {
    MissingAuthorizationHeaderError,
    InvalidAuthorizationHeaderError,
    ClaimNotAllowedError,
    MissingTokenError,
    RevokedTokenError
} from "../src/utilities/errors"

import * as jwt from "jsonwebtoken"

import { 
    Request, Response,
    NextFunction 
} from "express"

import { 
    IncomingHttpHeaders 
} from "http"

import * as fs from "fs"

describe("express-jwt-middleware should", function() {
    describe("be able to verify a JWT encrypted with", function() {
        const req: Request = new Object() as Request, res: Response = new Object() as Response;

        const SUBJECT: string = "615734d766e07fcf8cb24cb9";

        describe("HMAC encryption using", function() {
            const options: IOptions = {
                secret: "9RXFMNXHM4BY7I6ZW22TPBERA82FT9IM67QVI00V6M6AHE2SIXCSKXLED9L4L7CP"
            };

            it("HS256", function() {
                options.algorithm = "HS256";

                const token: string = jwt.sign(new Object(), options.secret, { algorithm: options.algorithm, subject: SUBJECT });
            
                req.headers = new Object() as IncomingHttpHeaders; req.headers["authorization"] = `Bearer ${token}`;
            
                middleware(options)(req, res, (error?: any) => expect(req.user.sub).toBe(SUBJECT));
            });

            it("HS384", function() {
                options.algorithm = "HS384";

                const token: string = jwt.sign(new Object(), options.secret, { algorithm: options.algorithm, subject: SUBJECT });
            
                req.headers = new Object() as IncomingHttpHeaders; req.headers["authorization"] = `Bearer ${token}`;
            
                middleware(options)(req, res, (error?: any) => expect(req.user.sub).toBe(SUBJECT));
            });

            it("HS512", function() {
                options.algorithm = "HS512";

                const token: string = jwt.sign(new Object(), options.secret, { algorithm: options.algorithm, subject: SUBJECT });
            
                req.headers = new Object() as IncomingHttpHeaders; req.headers["authorization"] = `Bearer ${token}`;
            
                middleware(options)(req, res, (error?: any) => expect(req.user.sub).toBe(SUBJECT));
            });
        });

        describe("RSASSA encryption using", function() {
            const 
                PUBLIC_KEY: Buffer = fs.readFileSync(__dirname + "/rsassa/public.pem"),
                PRIVATE_KEY: Buffer = fs.readFileSync(__dirname + "/rsassa/private.pem");

            const options: IOptions = {
                secret: PUBLIC_KEY
            };

            it("RS256", function() {
                options.algorithm = "RS256";

                const token: string = jwt.sign(new Object(), PRIVATE_KEY, { algorithm: options.algorithm, subject: SUBJECT });
            
                req.headers = new Object() as IncomingHttpHeaders; req.headers["authorization"] = `Bearer ${token}`;
            
                middleware(options)(req, res, (error?: any) => expect(req.user.sub).toBe(SUBJECT));
            });

            it("RS384", function() {
                options.algorithm = "RS384";

                const token: string = jwt.sign(new Object(), PRIVATE_KEY, { algorithm: options.algorithm, subject: SUBJECT });
            
                req.headers = new Object() as IncomingHttpHeaders; req.headers["authorization"] = `Bearer ${token}`;
            
                middleware(options)(req, res, (error?: any) => expect(req.user.sub).toBe(SUBJECT));
            });

            it("RS512", function() {
                options.algorithm = "RS512";

                const token: string = jwt.sign(new Object(), PRIVATE_KEY, { algorithm: options.algorithm, subject: SUBJECT });
            
                req.headers = new Object() as IncomingHttpHeaders; req.headers["authorization"] = `Bearer ${token}`;
            
                middleware(options)(req, res, (error?: any) => expect(req.user.sub).toBe(SUBJECT));
            });
        });

        describe("ECDSA encryption using", function() {
            it("ES256", function() {
                const options: IOptions = {
                    secret: fs.readFileSync(__dirname + "/ecdsa/secp256r1/public.pem"),
                    algorithm: "ES256"
                };

                const token: string = jwt.sign(new Object(), fs.readFileSync(__dirname + "/ecdsa/secp256r1/private.pem"), { algorithm: options.algorithm, subject: SUBJECT });
            
                req.headers = new Object() as IncomingHttpHeaders; req.headers["authorization"] = `Bearer ${token}`;
            
                middleware(options)(req, res, (error?: any) => expect(req.user.sub).toBe(SUBJECT));
            });

            it("ES384", function() {
                const options: IOptions = {
                    secret: fs.readFileSync(__dirname + "/ecdsa/secp384r1/public.pem"),
                    algorithm: "ES384"
                };

                const token: string = jwt.sign(new Object(), fs.readFileSync(__dirname + "/ecdsa/secp384r1/private.pem"), { algorithm: options.algorithm, subject: SUBJECT });
            
                req.headers = new Object() as IncomingHttpHeaders; req.headers["authorization"] = `Bearer ${token}`;
            
                middleware(options)(req, res, (error?: any) => expect(req.user.sub).toBe(SUBJECT));
            });

            it("ES512", function() {
                const options: IOptions = {
                    secret: fs.readFileSync(__dirname + "/ecdsa/secp521r1/public.pem"),
                    algorithm: "ES512"
                };

                const token: string = jwt.sign(new Object(), fs.readFileSync(__dirname + "/ecdsa/secp521r1/private.pem"), { algorithm: options.algorithm, subject: SUBJECT });
            
                req.headers = new Object() as IncomingHttpHeaders; req.headers["authorization"] = `Bearer ${token}`;
            
                middleware(options)(req, res, (error?: any) => expect(req.user.sub).toBe(SUBJECT));
            });
        });
    });

    describe("use next() to throw an instance of", function() {
        it("MissingAuthorizationHeaderError when the authorization header is missing", function() {

        });

        it("InvalidAuthorizationHeaderError when the authorization header is invalid", function() {

        });

        it("MissingTokenError when IOptions.retrieveJwt is implemented but returns null", function() {    

        });

        it("RevokedTokenError when IOptions.isRevoked is implemented but returns false", function() {    

        });

        it("ClaimNotAllowedError when IOptions.required_claims is set and one or more claims' values are invalid", function() {    

        });
    });

    describe("throw an Error if", function() {
        it("IOptions.secret is not set and process.env.EXPRESS_JWT_MIDDLEWARE_SECRET is null", function() {

        });

        it("IOptions.algorithm is not set and process.env.EXPRESS_JWT_MIDDLEWARE_ALGORITHM is null", function() {

        });
    });
});