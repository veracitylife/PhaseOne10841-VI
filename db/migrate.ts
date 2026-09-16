import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

const __dirname = dirname(fileURLToPath(import.meta.url));

async function main() {
  const databaseUrl =
    process.env.DATABASE_URL ?? 'postgres://phaseone:phaseone@localhost:5432/phaseone';
  const client = new pg.Client({ connectionString: databaseUrl });
  await client.connect();
  try {
    const dir = join(__dirname, 'migrations');
    const files = readdirSync(dir).filter((f) => f.endsWith('.sql')).sort();
    for (const file of files) {
      const sql = readFileSync(join(dir, file), 'utf8');
      console.log(`Applying ${file}...`);
      await client.query(sql);
    }
    console.log('Migrations complete.');
  } finally {
    await client.end();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
