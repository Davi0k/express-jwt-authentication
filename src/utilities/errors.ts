export class MissingAuthorizationHeaderError extends Error {
    public readonly name = "MissingAuthorizationHeaderError";

    constructor(message: string) {
        super(message);
    }
}

export class InvalidAuthorizationHeaderError extends Error {
    public readonly name = "InvalidAuthorizationHeaderError";

    constructor(message: string) {
        super(message);
    }
}

export class ClaimNotAllowedError extends Error {
    public readonly name = "ClaimNotAllowedError";

    constructor(message: string) {
        super(message);
    }
}

export class MissingTokenError extends Error {
    public readonly name = "MissingTokenError";

    constructor(message: string) {
        super(message);
    }
}

export class RevokedTokenError extends Error {
    public readonly name = "RevokedTokenError";

    constructor(message: string) {
        super(message);
    }
}