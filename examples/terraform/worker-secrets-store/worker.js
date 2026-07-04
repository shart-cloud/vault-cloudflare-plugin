export default {
  async fetch(_request, env) {
    const jwtPrivateKey = await env.JWT_PRIVATE_KEY.get();
    return new Response(`JWT key bytes: ${jwtPrivateKey.length}\n`);
  },
};
