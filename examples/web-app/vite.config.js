import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The app runs on 127.0.0.1 at a fixed port: FeatherAuth refuses "localhost" for
// a plain-http redirect URI, and the post-logout URL must match exactly.
const listen = { host: "127.0.0.1", port: 5173, strictPort: true };

export default defineConfig({
  plugins: [react()],
  server: listen,
  preview: listen,
});
