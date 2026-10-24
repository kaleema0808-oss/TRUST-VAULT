import "./load-env.js";
import { createApp, sanitizeErrorForLogging } from "./app.js";
import { loadConfig } from "./config.js";
import { MysqlAuthRepository, MysqlDocumentRepository } from "./auth/repository.js";
import { checkDatabaseConnection, pool } from "./db/pool.js";
import { runMigrations } from "./db/migrate.js";
import { provisionDefaultAccounts } from "./db/provision.js";
const config = loadConfig();

// Safely apply pending migrations on startup; abort startup if migration fails
try {
  const applied = await runMigrations();
  if (applied.length > 0) {
    console.info(`Applied ${applied.length} pending migration(s): ${applied.join(", ")}`);
  } else {
    console.info("Database migrations are up to date.");
  }
} catch (error) {
  console.error("Database migration execution failed on startup:", sanitizeErrorForLogging(error));
  await pool.end().catch(() => {});
  process.exit(1);
}

// Safely provision initial accounts if credentials are provided; abort if provisioning query fails
try {
  const provisionResult = await provisionDefaultAccounts(pool);
  if (provisionResult.provisioned.length > 0) {
    console.info(`Provisioned account(s): ${provisionResult.provisioned.join(", ")}`);
  }
  if (provisionResult.updated.length > 0) {
    console.info(`Updated account(s): ${provisionResult.updated.join(", ")}`);
  }
  if (provisionResult.skipped.length > 0) {
    console.info(`Provisioning status: ${provisionResult.skipped.join(", ")}`);
  }
} catch (error) {
  console.error("Account provisioning check failed on startup:", sanitizeErrorForLogging(error));
  await pool.end().catch(() => {});
  process.exit(1);
}

const app = createApp(
  new MysqlAuthRepository(pool),
  config,
  checkDatabaseConnection,
  new MysqlDocumentRepository(pool),
);
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
