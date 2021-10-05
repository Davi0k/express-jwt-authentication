import { 
    Request, Response, 
    NextFunction 
} from "express";

import * as jwt from "jsonwebtoken";

interface IOptions {
    secret?: jwt.Secret,
    algorithm?: jwt.Algorithm,
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
        //TODO
    };
}