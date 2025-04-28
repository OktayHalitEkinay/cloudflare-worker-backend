import { verifyJwt } from "../utils/auth";
import type { Env } from "../index";

export async function me(request: Request, env: Env): Promise<Response> {
	const authHeader = request.headers.get("Authorization");

	if (!authHeader || !authHeader.startsWith("Bearer ")) {
		return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
	}

	const token = authHeader.replace("Bearer ", "").trim();

	try {
		const payload = await verifyJwt(token, env.JWT_SECRET);

		return new Response(JSON.stringify({ user: { email: payload.email, role: payload.role } }), { status: 200 });
	} catch (err) {
		console.error(err);
		return new Response(JSON.stringify({ error: "Invalid token" }), { status: 401 });
	}
}
