import type { Env } from "../index";
import { hashPassword, generateSalt } from "../utils/password";
import { verifyJwt } from "../utils/auth";

export async function updateUser(request: Request, env: Env): Promise<Response> {
	const authHeader = request.headers.get("Authorization");

	if (!authHeader || !authHeader.startsWith("Bearer ")) {
		return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });
	}

	const token = authHeader.replace("Bearer ", "").trim();
	const body = await request.json() as { email?: string; password?: string };

	try {
		const payload = await verifyJwt(token, env.JWT_SECRET);

		if (!payload.email) {
			return new Response(JSON.stringify({ error: "Invalid token" }), { status: 401 });
		}

		const updates: string[] = [];
		const values: any[] = [];

		if (body.email) {
			updates.push("email = ?");
			values.push(body.email);
		}

		if (body.password) {
			const salt = generateSalt();
			const passwordHash = await hashPassword(body.password, salt);
			updates.push("password_hash = ?", "salt = ?");
			values.push(passwordHash, salt);
		}

		if (updates.length === 0) {
			return new Response(JSON.stringify({ error: "No update fields provided." }), { status: 400 });
		}

		values.push(payload.email); // Where condition

		await env.DB.prepare(
			`UPDATE users SET ${updates.join(", ")} WHERE email = ?`
		).bind(...values).run();

		return new Response(JSON.stringify({ message: "User updated successfully." }), { status: 200 });

	} catch (err) {
		console.error(err);
		return new Response(JSON.stringify({ error: "Internal server error" }), { status: 500 });
	}
}
