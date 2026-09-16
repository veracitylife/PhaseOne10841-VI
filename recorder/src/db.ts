import pg from 'pg';

let pool: pg.Pool | null = null;

export function getPool(): pg.Pool {
  if (!pool) {
    const connectionString =
      process.env.DATABASE_URL ?? 'postgres://phaseone:phaseone@localhost:5432/phaseone';
    pool = new pg.Pool({ connectionString, max: 10 });
  }
  return pool;
}

export async function withClient<T>(fn: (client: pg.PoolClient) => Promise<T>): Promise<T> {
  const client = await getPool().connect();
  try {
    return await fn(client);
  } finally {
    client.release();
  }
}

export async function healthCheck(): Promise<boolean> {
  try {
    const r = await getPool().query('SELECT 1');
    return r.rowCount === 1;
  } catch {
    return false;
  }
}
