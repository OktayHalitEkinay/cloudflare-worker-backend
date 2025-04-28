import { hashPassword } from "../utils/password";
import { createJwt } from "../utils/auth";
import type { Env } from "../index";


export async function login(request: Request, env: Env): Promise<Response> {
    const body = await request.json() as { email: string; password: string };
    const { email, password } = body;

    if (!email || !password) {
        return new Response(JSON.stringify({ error: "Email and password required." }), { status: 400 });
    }

    const user = await env.DB.prepare(`SELECT * FROM users WHERE email = ?`)
        .bind(email)
        .first<{ id: number, email: string, password_hash: string, salt: string, role: string }>();

    if (!user) {
        return new Response(JSON.stringify({ error: "Invalid credentials." }), { status: 401 });
    }

    const incomingPasswordHash = await hashPassword(password, user.salt);

    if (incomingPasswordHash !== user.password_hash) {
        return new Response(JSON.stringify({ error: "Invalid credentials." }), { status: 401 });
    }

    const accessToken = await createJwt({ email: user.email, role: user.role }, env.JWT_SECRET, "15m");
    const refreshToken = await createJwt({ email: user.email, role: user.role }, env.JWT_SECRET, "7d");

    return new Response(JSON.stringify({ accessToken, refreshToken }), { status: 200 });
}
