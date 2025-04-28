export interface Env {
	DB: D1Database;
  }
  
  // Şifreyi hashleyen fonksiyon (PBKDF2 + SHA-256)
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
		iterations: 100_000, // Çok güçlü yapıyoruz
		hash: "SHA-256",
	  },
	  key,
	  256
	);
  
	const hashArray = Array.from(new Uint8Array(derivedBits));
	const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
	return hashHex;
  }
  
  // Salt üreten yardımcı fonksiyon
  function generateSalt(length: number = 16): string {
	const array = new Uint8Array(length);
	crypto.getRandomValues(array);
	return Array.from(array)
	  .map((b) => b.toString(16).padStart(2, "0"))
	  .join("");
  }
  
  async function register(request: Request, env: Env): Promise<Response> {
	const body = await request.json() as { email: string; password: string };
	const { email, password } = body;
  
	if (!email || !password) {
	  return new Response(JSON.stringify({ error: "Email and password required." }), {
		status: 400,
		headers: { "Content-Type": "application/json" },
	  });
	}
  
	const salt = generateSalt(); // Kullanıcıya özel salt üretiyoruz
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
  
  export default {
	async fetch(request: Request, env: Env): Promise<Response> {
	  const url = new URL(request.url);
  
	  if (request.method === "POST" && url.pathname === "/api/register") {
		return register(request, env);
	  }
  
	  return new Response("Not Found", { status: 404 });
	},
  };
  