import type { Env } from "../index";
import { hashPassword, generateSalt } from "../utils/password";
import { verifyJwt } from "../utils/auth";

export async function createUser(request: Request, env: Env): Promise<Response> {
    const authHeader = request.headers.get("Authorization");

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
    }

    const token = authHeader.replace("Bearer ", "").trim();
    const body = await request.json() as { email: string; password: string; role: string };

    try {
        const payload = await verifyJwt(token, env.JWT_SECRET);

        if (payload.role !== "admin") {
            return new Response(JSON.stringify({ error: "Forbidden. Only admins can create users." }), { status: 403 });
        }

        if (!body.email || !body.password || !body.role) {
            return new Response(JSON.stringify({ error: "Email, password and role are required." }), { status: 400 });
        }

        const allowedRoles = ["user", "admin"];
        if (!allowedRoles.includes(body.role)) {
            return new Response(JSON.stringify({ error: "Invalid role." }), { status: 400 });
        }

        const salt = generateSalt();
        const passwordHash = await hashPassword(body.password, salt);

        await env.DB.prepare(
            `INSERT INTO users (email, password_hash, salt, role) VALUES (?, ?, ?, ?)`
        ).bind(body.email, passwordHash, salt, body.role).run();

        return new Response(JSON.stringify({ message: "User created successfully." }), { status: 201 });

    } catch (err) {
        console.error(err);
        return new Response(JSON.stringify({ error: "Internal server error" }), { status: 500 });
    }
}
