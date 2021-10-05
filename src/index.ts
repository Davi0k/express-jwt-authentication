import { 
    Request, Response, 
    NextFunction 
} from "express";

import * as jwt from "jsonwebtoken";

export interface IOptions {
    secret?: jwt.Secret,
    algorithm?: jwt.Algorithm,
    guest?: boolean,

    required?: {
        [key: string]: string[]
    },

    validation: (payload: jwt.JwtPayload) => boolean,
    
    retrieveJWT?: (req: Request, res: Response, next: NextFunction) => string
}

export default function(options?: IOptions) {
    if (!options.secret)
        if (process.env.EXPRESS_JWT_MIDDLEWARE_SECRET)
            options.secret = (process.env.EXPRESS_JWT_MIDDLEWARE_SECRET as jwt.Secret);
        else throw new Error("secret should be set");

    if (!options.algorithm)
        if (process.env.EXPRESS_JWT_MIDDLEWARE_SECRET)
            options.algorithm = (process.env.EXPRESS_JWT_MIDDLEWARE_ALGORITHM as jwt.Algorithm);
        else throw new Error("algorithm should be set");

    return (req: Request, res: Response, next: NextFunction) => {
        let token: string | null = null;

        if (!options.retrieveJWT) {
            const header: string = req.headers.authorization?.trim();

            if (!header)
                if (!options.guest)
                    throw new Error("It is necessary to provide an Authorization header containing the access token.");
                else return next();

            const pattern = /^(Bearer)[\s]+[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*\.[A-Za-z0-9-_]*$/gi;

            if (!pattern.test(header))
                throw new Error("The content of the Authorization header does not match the format: Bearer [JWT].");

            token = header.split(" ")[1];
        }

        jwt.verify(token, options.secret, (error, user) => {
            if (error)
                throw new Error("The JWT used for authentication is not valid.");

            if (options.required) {
                for (const key of Object.keys(user)) {
                    if (options.required[key])
                        if (!options.required[key].includes(user[key]))
                            throw new Error("Property not allowed");
                }
            }

            req.user = user;

            return next();
        });
    };
}