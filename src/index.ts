import { register } from "./handlers/register";
import { login } from "./handlers/login";
import { refreshToken } from "./handlers/refresh";
import { me } from "./handlers/me";
import { logout } from "./handlers/logout";
import { updateUser } from "./handlers/updateUser";
import { deleteUser } from "./handlers/deleteUser";
import { createUser } from "./handlers/createUser";
import { listUsers } from "./handlers/listUsers";

export interface Env {
	DB: D1Database;
	JWT_SECRET: string;
}

// CORS Header üreten yardımcı fonksiyon
function getCorsHeaders() {
	return {
		"Access-Control-Allow-Origin": "*", // İstersen buraya sadece localhost:3000 veya domainini de yazabilirsin
		"Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
		"Access-Control-Allow-Headers": "Content-Type, Authorization",
	};
}

// Response'lara CORS header ekleyen yardımcı
function withCors(response: Response) {
	const newHeaders = new Headers(response.headers);
	const corsHeaders = getCorsHeaders();
	for (const [key, value] of Object.entries(corsHeaders)) {
		newHeaders.set(key, value);
	}

	return new Response(response.body, {
		status: response.status,
		statusText: response.statusText,
		headers: newHeaders,
	});
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);

		// 👉 OPTIONS preflight isteklerini cevapla
		if (request.method === "OPTIONS") {
			return new Response(null, {
				status: 204,
				headers: getCorsHeaders(),
			});
		}

		let response: Response;

		// Normal istekleri yönlendiriyoruz
		if (request.method === "POST" && url.pathname === "/api/register") {
			response = await register(request, env);
		} else if (request.method === "POST" && url.pathname === "/api/login") {
			response = await login(request, env);
		} else if (request.method === "POST" && url.pathname === "/api/refresh") {
			response = await refreshToken(request, env);
		} else if (request.method === "GET" && url.pathname === "/api/me") {
			response = await me(request, env);
		} else if (request.method === "POST" && url.pathname === "/api/logout") {
			response = await logout(request, env);
		} else if (request.method === "POST" && url.pathname === "/api/users/update") {
			response = await updateUser(request, env);
		} else if (request.method === "DELETE" && url.pathname === "/api/users/delete") {
			response = await deleteUser(request, env);
		} else if (request.method === "POST" && url.pathname === "/api/users/create") {
			response = await createUser(request, env);
		} else if (request.method === "GET" && url.pathname === "/api/users") {
			response = await listUsers(request, env);
		} else {
			// Bulunamayan endpoint
			response = new Response("Not Found", { status: 404 });
		}

		// 🎯 Her response'a CORS header ekle
		return withCors(response);
	},
};
