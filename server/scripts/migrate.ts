import 'dotenv/config';
import { migrate, pool } from '../worker/migrate';

migrate()
  .then((a) => console.log(a.length ? `applied: ${a.join(', ')}` : 'up to date'))
  .finally(() => pool.end());
