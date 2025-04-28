import { verifyJwt, createJwt } from "../utils/auth";
import type { Env } from "../index";

export async function refreshToken(request: Request, env: Env): Promise<Response> {
	const body = await request.json() as { refreshToken: string };
	const { refreshToken } = body;

	if (!refreshToken) {
		return new Response(JSON.stringify({ error: "Refresh token required." }), { status: 400 });
	}

	try {
		const payload = await verifyJwt(refreshToken, env.JWT_SECRET);

		if (!payload.email || !payload.role) {
			throw new Error("Invalid refresh token payload.");
		}

		const newAccessToken = await createJwt({ email: payload.email, role: payload.role }, env.JWT_SECRET, "15m");

		return new Response(JSON.stringify({ accessToken: newAccessToken }), { status: 200 });
	} catch (err) {
		console.error(err);
		return new Response(JSON.stringify({ error: "Invalid refresh token" }), { status: 401 });
	}
}
