export const config = {
    auth: {
      issuer: process.env.ISSUER_URL,
      client_id: process.env.CLIENT_ID,
      client_secret: process.env.CLIENT_SECRET,
      redirect_uri: 'http://localhost:5173/callback'
    }
  };