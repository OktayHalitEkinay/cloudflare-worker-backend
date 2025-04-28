import type { Env } from "../index";
import { verifyJwt } from "../utils/auth";

export async function deleteUser(request: Request, env: Env): Promise<Response> {
    const authHeader = request.headers.get("Authorization");

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
    }

    const token = authHeader.replace("Bearer ", "").trim();
    const body = await request.json() as { email: string };

    try {
        const payload = await verifyJwt(token, env.JWT_SECRET);

        if (payload.role !== "admin") {
            return new Response(JSON.stringify({ error: "Forbidden. Only admins can delete users." }), { status: 403 });
        }

        if (!body.email) {
            return new Response(JSON.stringify({ error: "Target user email required." }), { status: 400 });
        }

        await env.DB.prepare(`DELETE FROM users WHERE email = ?`)
            .bind(body.email)
            .run();

        return new Response(JSON.stringify({ message: "User deleted successfully." }), { status: 200 });

    } catch (err) {
        console.error(err);
        return new Response(JSON.stringify({ error: "Internal server error" }), { status: 500 });
    }
}
