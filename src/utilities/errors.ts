export class MissingAuthorizationHeaderError extends Error {
    public name = "MissingAuthorizationHeaderError";

    constructor(message: string) {
        super(message);
    }
}

export class InvalidAuthorizationHeaderError extends Error {
    public name = "InvalidAuthorizationHeaderError";

    constructor(message: string) {
        super(message);
    }
}

export class PropertyNotAllowedError extends Error {
    public name = "PropertyNotAllowedError";

    constructor(message: string) {
        super(message);
    }
}