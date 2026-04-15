#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { Client } = require('pg');

const action = process.argv[2];
const targetPath = process.argv[3];

if (!['backup', 'reset', 'prune-funcionarios-ativos'].includes(action)) {
  console.error('Uso: node scripts/db-maintenance.js <backup|reset|prune-funcionarios-ativos> [arquivo]');
  process.exit(1);
}

const client = new Client({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function listarTabelasPublicas() {
  const r = await client.query(`
    SELECT tablename
    FROM pg_tables
    WHERE schemaname = 'public'
    ORDER BY tablename
  `);
  return r.rows.map(row => row.tablename);
}

async function gerarBackup() {
  const tabelas = await listarTabelasPublicas();
  const backup = {
    createdAt: new Date().toISOString(),
    tables: {}
  };

  for (const tabela of tabelas) {
    const r = await client.query(`SELECT * FROM "${tabela}"`);
    backup.tables[tabela] = r.rows;
  }

  const arquivo = targetPath || `/tmp/scap-backup-${Date.now()}.json`;
  fs.writeFileSync(path.resolve(arquivo), JSON.stringify(backup, null, 2));
  console.log(JSON.stringify({
    ok: true,
    action: 'backup',
    path: arquivo,
    tableCount: tabelas.length
  }));
}

async function resetarBanco() {
  const todasAsTabelas = await listarTabelasPublicas();
  const preservadas = new Set(['funcionarios']);
  const limpar = todasAsTabelas.filter(tabela => !preservadas.has(tabela));

  await client.query('BEGIN');
  try {
    if (limpar.length) {
      const sql = `TRUNCATE TABLE ${limpar.map(tabela => `"${tabela}"`).join(', ')} RESTART IDENTITY CASCADE`;
      await client.query(sql);
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  }

  const funcionarios = await client.query('SELECT COUNT(*)::int AS total FROM funcionarios');
  console.log(JSON.stringify({
    ok: true,
    action: 'reset',
    preservedTables: ['funcionarios'],
    truncatedTables: limpar,
    funcionarios: funcionarios.rows[0].total
  }));
}

async function limparFuncionariosInativos() {
  await client.query('BEGIN');
  try {
    const antes = await client.query('SELECT COUNT(*)::int AS total FROM funcionarios');
    const ativos = await client.query(`SELECT COUNT(*)::int AS total FROM funcionarios WHERE COALESCE(status, 'ativo') = 'ativo'`);
    await client.query(`DELETE FROM funcionarios WHERE COALESCE(status, 'ativo') <> 'ativo'`);
    await client.query('COMMIT');
    console.log(JSON.stringify({
      ok: true,
      action: 'prune-funcionarios-ativos',
      before: antes.rows[0].total,
      after: ativos.rows[0].total,
      removed: antes.rows[0].total - ativos.rows[0].total
    }));
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  }
}

(async () => {
  await client.connect();
  if (action === 'backup') await gerarBackup();
  if (action === 'reset') await resetarBanco();
  if (action === 'prune-funcionarios-ativos') await limparFuncionariosInativos();
  await client.end();
})().catch(async err => {
  console.error(err.stack || err.message || String(err));
  try { await client.end(); } catch (_) {}
  process.exit(1);
});
