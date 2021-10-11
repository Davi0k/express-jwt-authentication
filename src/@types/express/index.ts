/* eslint-disable */

declare namespace Express {
    interface Request {
        user?: import("jsonwebtoken").JwtPayload
    }
}