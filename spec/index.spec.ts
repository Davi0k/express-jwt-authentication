/* eslint-disable */

import middleware, { IOptions } from "../src";

import {
    MissingAuthorizationHeaderError,
    InvalidAuthorizationHeaderError,
    PropertyNotAllowedError,
    MissingTokenError,
    RevokedTokenError
} from "../src/utilities/errors"

import * as jwt from "jsonwebtoken";

import { 
    Request, Response,
    NextFunction 
} from "express";

import { 
    IncomingHttpHeaders 
} from "http";

describe("express-jwt-middleware should", function() {
    describe("be able to verify a JWT encrypted with HS256 (symmetric encryption)", function() {
        describe("and contained in the authorization header", function() {
            it("with IOptions.allow_guests set to false", function() {

            });

            it("with IOptions.allow_guests set to true", function() {

            });

            it("with IOptions.required_claims set", function() {

            });
        });

        describe("and returned by IOptions.retrieveJwt", function() {
            it("with IOptions.allow_guests set to false", function() {

            });

            it("with IOptions.allow_guests set to true", function() {

            });

            it("with IOptions.required_claims set", function() {

            });
        });
    });

    describe("be able to verify a JWT encrypted with RS256 (asymmetric encryption)", function() {
        describe("and contained in the authorization header", function() {
            it("with IOptions.allow_guests set to false", function() {

            });

            it("with IOptions.allow_guests set to true", function() {

            });

            it("with IOptions.required_claims set", function() {

            });
        });

        describe("and returned by IOptions.retrieveJwt", function() {
            it("with IOptions.allow_guests set to false", function() {

            });

            it("with IOptions.allow_guests set to true", function() {

            });

            it("with IOptions.required_claims set", function() {

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

        it("PropertyNotAllowedError when IOptions.required_claims is set and one or more claims' values are invalid", function() {    

        });

        it("RevokedTokenError when the token has expired and is no longer valid", function() {    

        });
    });

    describe("throw an Error if", function() {
        it("IOptions.secret is not set and process.env.EXPRESS_JWT_MIDDLEWARE_SECRET is null", function() {

        });

        it("IOptions.algorithm is not set and process.env.EXPRESS_JWT_MIDDLEWARE_ALGORITHM is null", function() {

        });
    });
});