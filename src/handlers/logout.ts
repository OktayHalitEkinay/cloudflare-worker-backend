export async function logout(request: Request, env: Env): Promise<Response> {
	return new Response(JSON.stringify({ message: "Logout successful." }), { status: 200 });
}
