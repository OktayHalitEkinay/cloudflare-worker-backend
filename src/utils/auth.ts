import { SignJWT, jwtVerify, type JWTPayload } from "jose";

export async function verifyJwt(token: string, secret: string) {
    const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["verify"]
    );

    const { payload } = await jwtVerify(token, key, {
        algorithms: ["HS256"],
    });

    return payload;
}

export async function createJwt(payload: JWTPayload, secret: string, expiresIn: string) {
    const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );

    return await new SignJWT(payload)
        .setProtectedHeader({ alg: "HS256" })
        .setIssuedAt()
        .setExpirationTime(expiresIn)
        .sign(key);
}
