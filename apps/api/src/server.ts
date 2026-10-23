import "./load-env.js";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { MysqlAuthRepository } from "./auth/repository.js";
import { checkDatabaseConnection, pool } from "./db/pool.js";

const config = loadConfig();
const app = createApp(new MysqlAuthRepository(pool), config, checkDatabaseConnection);
const server = app.listen(config.apiPort, "0.0.0.0", () => {
  console.info(`TrustVault API listening on port ${config.apiPort}`);
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    server.close(() => {
      void pool.end().finally(() => process.exit(0));
    });
  });
}
