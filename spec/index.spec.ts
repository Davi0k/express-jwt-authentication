import middleware, { IOptions } from "../src"

import {
    MissingAuthorizationHeaderError,
    InvalidAuthorizationHeaderError,
    ClaimNotAllowedError,
    MissingTokenError,
    RevokedTokenError
} from "../src/utilities/errors"

import { 
    Request, Response,
    NextFunction 
} from "express"

import { 
    IncomingHttpHeaders 
} from "http"

import * as jwt from "jsonwebtoken"

import * as fs from "fs"

describe("express-jwt-middleware should", function() {
    const EMPTY = "";

    describe("be able to verify a JWT encrypted with", function() {
        const req: Request = new Object() as Request, res: Response = new Object() as Response;

        const SUBJECT = "615734d766e07fcf8cb24cb9";

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

    describe("allow the user to set", function() {
        const SUBJECT = "61642b0caa086e7f7f78a0d3";

        describe("IOptions.retrieveJwt", function() {
            const token: string = jwt.sign(new Object(), EMPTY, { algorithm: "none", subject: SUBJECT });

            const req: Request = new Object() as Request, res: Response = new Object() as Response;

            it("to manually return a valid JWT instead of using the authorization header", function() {
                const options: IOptions = {
                    secret: EMPTY, 
                    algorithm: "none",
                    retrieveJwt: (req: Request, res: Response, next: NextFunction): string | null => token
                };
        
                middleware(options)(req, res, (error?: any) => expect(req.user.sub).toBe(SUBJECT));
            });

            it("using next() to throw an instance of MissingTokenError when set but returning null", function() {
                const options: IOptions = {
                    secret: EMPTY, 
                    algorithm: "none",
                    retrieveJwt: (req: Request, res: Response, next: NextFunction): string | null => null
                };
        
                middleware(options)(req, res, (error?: any) => expect(error).toBeInstanceOf(MissingTokenError));
            });
        });

        describe("IOptions.isRevoked", function() {
            const token: string = jwt.sign(new Object(), EMPTY, { algorithm: "none", subject: SUBJECT });

            const req: Request = new Object() as Request, res: Response = new Object() as Response;

            req.headers = new Object() as IncomingHttpHeaders; req.headers["authorization"] = `Bearer ${token}`;

            it("to check if the JWT has been revoked previously", function() {
                const options: IOptions = {
                    secret: EMPTY, 
                    algorithm: "none",
                    isRevoked: (payload: jwt.JwtPayload): boolean => false
                };
        
                middleware(options)(req, res, (error?: any) => expect(req.user.sub).toBe(SUBJECT));
            });

            it("using next() to throw an instance of RevokedTokenError when set and returning true", function() {
                const options: IOptions = {
                    secret: EMPTY, 
                    algorithm: "none",
                    isRevoked: (payload: jwt.JwtPayload): boolean => true
                };

                middleware(options)(req, res, (error?: any) => expect(error).toBeInstanceOf(RevokedTokenError));
            });
        });
    });

    describe("permit the user to set IOptions.required_claims", function() {
        const SUBJECT = "61642af784fd8a12cd057af4";

        const payload: jwt.JwtPayload = {
            "role": [ "moderator", "administrator" ][Math.floor(Math.random() * 2)],
            "iss": "http://localhost:3000"
        };

        const token: string = jwt.sign(payload, EMPTY, { algorithm: "none", subject: SUBJECT });

        const req: Request = new Object() as Request, res: Response = new Object() as Response;

        req.headers = new Object() as IncomingHttpHeaders; req.headers["authorization"] = `Bearer ${token}`;

        it("to make the JWT valid only if one or more specific claims and respective acceptable values are signed in the token", function() {
            const options: IOptions = {
                secret: EMPTY, 
                algorithm: "none",
                required_claims: { 
                    "role": [ "moderator", "administrator" ],
                    "iss": [ "http://localhost:3000" ]
                }
            };
    
            middleware(options)(req, res, (error?: any) => expect(req.user.sub).toBe(SUBJECT));
        });

        it("using next() to throw an instance of ClaimNotAllowedError when set and one or more claims are not acceptable", function() {
            const options: IOptions = {
                secret: EMPTY, 
                algorithm: "none",
                required_claims: { 
                    "role": [ "moderator", "administrator" ],
                    "iss": [ "http://localhost:5000" ]
                }
            };
    
            middleware(options)(req, res, (error?: any) => expect(error).toBeInstanceOf(ClaimNotAllowedError));
        });
    });

    describe("permit guest authentication when IOptions.allow_guests is set to true and no JWT is provided by the", function() {
        const req: Request = new Object() as Request, res: Response = new Object() as Response;
    
        req.headers = new Object() as IncomingHttpHeaders;
    
        it("authorization header", function() {
            const options: IOptions = {
                secret: EMPTY, 
                algorithm: "none",
                allow_guests: true,
                retrieveJwt: undefined
            };
    
            middleware(options)(req, res, (error?: any) => expect(error == undefined && req.user == undefined).toBeTrue());
        });
    
        it("IOptions.retrieveJwt method", function() {
            const options: IOptions = {
                secret: EMPTY, 
                algorithm: "none",
                allow_guests: true,
                retrieveJwt: (req: Request, res: Response, next: NextFunction): string | null => null
            };
    
            middleware(options)(req, res, (error?: any) => expect(error == undefined && req.user == undefined).toBeTrue());
        });
    });

    describe("use next() to throw an instance of", function() {
        const options: IOptions = {
            secret: EMPTY, 
            algorithm: "none"
        };

        const req: Request = new Object() as Request, res: Response = new Object() as Response;

        it("MissingAuthorizationHeaderError when the authorization header is missing", function() {
            req.headers = new Object() as IncomingHttpHeaders; req.headers["authorization"] = null;

            middleware(options)(req, res, (error?: any) => expect(error).toBeInstanceOf(MissingAuthorizationHeaderError));
        });

        it("InvalidAuthorizationHeaderError when the authorization header is invalid", function() {
            req.headers = new Object() as IncomingHttpHeaders; req.headers["authorization"] = "Invalid Authorization Header";

            middleware(options)(req, res, (error?: any) => expect(error).toBeInstanceOf(InvalidAuthorizationHeaderError));
        });
    });

    describe("throw an Error if", function() {
        it("IOptions.secret is not set and process.env.EXPRESS_JWT_MIDDLEWARE_SECRET is null", function() {
            expect(() => middleware({ secret: null, algorithm: "none" })).toThrowError("Property `secret` must be set either in IOptions parameter or in process.env.");
        });

        it("IOptions.algorithm is not set and process.env.EXPRESS_JWT_MIDDLEWARE_ALGORITHM is null", function() {
            expect(() => middleware({ secret: EMPTY, algorithm: null })).toThrowError("Property `algorithm` must be set either in IOptions parameter or in process.env.");
        });
    });
});