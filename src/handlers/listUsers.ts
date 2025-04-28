import type { Env } from "../index";
import { verifyJwt } from "../utils/auth";

export async function listUsers(request: Request, env: Env): Promise<Response> {
    const authHeader = request.headers.get("Authorization");

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
    }

    const token = authHeader.replace("Bearer ", "").trim();

    try {
        const payload = await verifyJwt(token, env.JWT_SECRET);

        if (payload.role !== "admin") {
            return new Response(JSON.stringify({ error: "Forbidden. Only admins can view users." }), { status: 403 });
        }

        const users = await env.DB.prepare(`SELECT id, email, role FROM users`).all<{ id: number, email: string, role: string }>();

        return new Response(JSON.stringify({ users: users.results }), { status: 200 });

    } catch (err) {
        console.error(err);
        return new Response(JSON.stringify({ error: "Internal server error" }), { status: 500 });
    }
}
