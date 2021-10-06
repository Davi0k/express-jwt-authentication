import { 
    Request, Response, 
    NextFunction 
} from "express";

import {
    MissingAuthorizationHeaderError,
    InvalidAuthorizationHeaderError,
    PropertyNotAllowedError,
    MissingTokenError
} from "./utilities/errors"

import * as jwt from "jsonwebtoken";

export interface IOptions {
    secret?: jwt.Secret,
    algorithm?: jwt.Algorithm,
    guest?: boolean,

    required?: {
        [key: string]: string[]
    },

    validation?: (payload: jwt.JwtPayload) => boolean,
    
    retrieveJWT?: (req?: Request, res?: Response, next?: NextFunction) => string | null
}

export default function(options?: IOptions): (req: Request, res: Response, next: NextFunction) => void {
    if (!options.secret)
        if (process.env.EXPRESS_JWT_MIDDLEWARE_SECRET)
            options.secret = (process.env.EXPRESS_JWT_MIDDLEWARE_SECRET as jwt.Secret);
        else throw new Error("Property `secret` must be set either in IOptions parameter or in process.env.");

    if (!options.algorithm)
        if (process.env.EXPRESS_JWT_MIDDLEWARE_SECRET)
            options.algorithm = (process.env.EXPRESS_JWT_MIDDLEWARE_ALGORITHM as jwt.Algorithm);
        else throw new Error("Property `algorithm` must be set either in IOptions parameter or in process.env.");

    return (req: Request, res: Response, next: NextFunction): void => {
        let token: string | null;

        if (options.retrieveJWT) {
            token = options.retrieveJWT(req, res, next);

            if (!token)
                if (!options.guest)
                    return next(new MissingTokenError("A valid access token must be provided for authentication."));
                else return next();
        } 

        if (!options.retrieveJWT) {
            const header: string = req.headers.authorization?.trim();

            if (!header)
                if (!options.guest)
                    return next(new MissingAuthorizationHeaderError("It is necessary to provide an Authorization header containing the access token."));
                else return next();

            const pattern = /^(Bearer)[\s]+[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*$/gi;

            if (!pattern.test(header))
                return next(new InvalidAuthorizationHeaderError("The content of the Authorization header does not match the format: Bearer [JWT]."));

            token = header.split(" ").pop();
        }

        jwt.verify(token, options.secret, { algorithms: [options.algorithm] }, (error: jwt.VerifyErrors, user: jwt.JwtPayload): void => {
            if (error)
                return next(error);

            if (options.required)
                for (const key of Object.keys(options.required)) {
                    if (user[key]) 
                        if (options.required[key].includes(user[key]))
                            continue;

                    return next(new PropertyNotAllowedError(`Claim <${key}> only accepts <${options.required[key]}> values. <${user[key]}> is not acceptable.`));
                }
                    
            req.user = user;

            return next();
        });
    };
}