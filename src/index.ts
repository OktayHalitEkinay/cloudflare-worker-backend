import { SignJWT } from "jose";


export interface Env {
	DB: D1Database;
	JWT_SECRET: string;
}

// Şifreyi PBKDF2 ile hashleyen fonksiyon
async function hashPassword(password: string, salt: string): Promise<string> {
	const encoder = new TextEncoder();
	const passwordBuffer = encoder.encode(password);
	const saltBuffer = encoder.encode(salt);

	const key = await crypto.subtle.importKey(
		"raw",
		passwordBuffer,
		"PBKDF2",
		false,
		["deriveBits"]
	);

	const derivedBits = await crypto.subtle.deriveBits(
		{
			name: "PBKDF2",
			salt: saltBuffer,
			iterations: 100_000,
			hash: "SHA-256",
		},
		key,
		256
	);

	const hashArray = Array.from(new Uint8Array(derivedBits));
	const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
	return hashHex;
}

// Random salt üreten fonksiyon
function generateSalt(length: number = 16): string {
	const array = new Uint8Array(length);
	crypto.getRandomValues(array);
	return Array.from(array)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

// Kullanıcı kayıt işlemi (/api/register)
async function register(request: Request, env: Env): Promise<Response> {
	const body = await request.json() as { email: string; password: string };
	const { email, password } = body;

	if (!email || !password) {
		return new Response(JSON.stringify({ error: "Email and password required." }), {
			status: 400,
			headers: { "Content-Type": "application/json" },
		});
	}

	const salt = generateSalt();
	const passwordHash = await hashPassword(password, salt);

	try {
		await env.DB.prepare(
			`INSERT INTO users (email, password_hash, salt) VALUES (?, ?, ?)`
		)
			.bind(email, passwordHash, salt)
			.run();

		return new Response(JSON.stringify({ message: "User registered successfully." }), {
			status: 201,
			headers: { "Content-Type": "application/json" },
		});
	} catch (err: any) {
		if (err.message.includes('UNIQUE constraint failed')) {
			return new Response(JSON.stringify({ error: "Email already exists." }), {
				status: 409,
				headers: { "Content-Type": "application/json" },
			});
		}

		console.error(err);
		return new Response(JSON.stringify({ error: "Internal server error." }), {
			status: 500,
			headers: { "Content-Type": "application/json" },
		});
	}
}

// Kullanıcı login işlemi (/api/login)
async function login(request: Request, env: Env): Promise<Response> {
	const body = await request.json() as { email: string; password: string };
	const { email, password } = body;

	if (!email || !password) {
		return new Response(JSON.stringify({ error: "Email and password required." }), {
			status: 400,
			headers: { "Content-Type": "application/json" },
		});
	}

	const user = await env.DB.prepare(
		`SELECT * FROM users WHERE email = ?`
	).bind(email).first<{ id: number, email: string, password_hash: string, salt: string }>();

	if (!user) {
		return new Response(JSON.stringify({ error: "Invalid credentials." }), {
			status: 401,
			headers: { "Content-Type": "application/json" },
		});
	}

	const incomingPasswordHash = await hashPassword(password, user.salt);

	if (incomingPasswordHash !== user.password_hash) {
		return new Response(JSON.stringify({ error: "Invalid credentials." }), {
			status: 401,
			headers: { "Content-Type": "application/json" },
		});
	}

	// 💥 BURASI KRİTİK: Secret'ı CryptoKey formatına çeviriyoruz
	const key = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(env.JWT_SECRET),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"]
	);

	const token = await new SignJWT({ email: user.email })
		.setProtectedHeader({ alg: "HS256" })
		.setIssuedAt()
		.setExpirationTime("2h")
		.sign(key);

	return new Response(JSON.stringify({ token }), {
		status: 200,
		headers: { "Content-Type": "application/json" },
	});
}


// Worker Fetch Fonksiyonu
export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);

		if (request.method === "POST" && url.pathname === "/api/register") {
			return register(request, env);
		}

		if (request.method === "POST" && url.pathname === "/api/login") {
			return login(request, env);
		}

		return new Response("Not Found", { status: 404 });
	},
};
