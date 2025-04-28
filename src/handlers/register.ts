import { hashPassword, generateSalt } from "../utils/password";
import type { Env } from "../index";

export async function register(request: Request, env: Env): Promise<Response> {
	const body = await request.json() as { email: string; password: string; role: string };
	const { email, password, role } = body;

	if (!email || !password || !role) {
		return new Response(JSON.stringify({ error: "Email, password and role required." }), { status: 400 });
	}

	const allowedRoles = ["user", "admin"];
	if (!allowedRoles.includes(role)) {
		return new Response(JSON.stringify({ error: "Invalid role." }), { status: 400 });
	}

	const salt = generateSalt();
	const passwordHash = await hashPassword(password, salt);

	try {
		await env.DB.prepare(
			`INSERT INTO users (email, password_hash, salt, role) VALUES (?, ?, ?, ?)`
		).bind(email, passwordHash, salt, role).run();

		return new Response(JSON.stringify({ message: "User registered successfully." }), { status: 201 });
	} catch (err: any) {
		if (err.message.includes('UNIQUE constraint failed')) {
			return new Response(JSON.stringify({ error: "Email already exists." }), { status: 409 });
		}
		console.error(err);
		return new Response(JSON.stringify({ error: "Internal server error." }), { status: 500 });
	}
}
