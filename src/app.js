import "dotenv/config";
import express from "express";
import routes from "./routes/index.js";
import { connectDb } from "./config/db.js";

const app = express();

app.use(express.json());
app.use("/api", routes);

app.use((err, _req, res, _next) => {
  const status = err.statusCode ?? 500;
  const message = err.message ?? "Internal Server Error";
  res.status(status).json({ error: message });
});

export default app;

const port = Number(process.env.PORT) || 3000;
const mongoUri = process.env.MONGODB_URI;

if (!mongoUri) {
  console.error("Missing MONGODB_URI. Copy .env.example to .env and set it.");
  process.exit(1);
}

try {
  await connectDb(mongoUri);
  console.log("Connected to MongoDB");
  app.listen(port, () => {
    console.log(`Listening on port ${port} (http://localhost:${port})`);
  });
} catch (err) {
  console.error("Failed to start:", err.message);
  process.exit(1);
}
