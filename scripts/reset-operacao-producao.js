#!/usr/bin/env node
const { Client } = require('pg');

const TABELAS_LIMPAR = [
  'clientes',
  'enderecos_cliente',
  'vendas',
  'venda_itens',
  'venda_pagamentos',
  'caixa',
  'caixa_movimentos',
  'orcamentos',
  'orcamento_itens',
  'creditos_clientes',
  'vales_funcionarios',
  'vale_itens',
  'ponto',
  'cheques',
  'estoque_movimentos',
  'atendimentos_pdv',
  'auditoria',
  'metas_comissao'
];

function quoteTableName(nome) {
  return `"${String(nome).replace(/"/g, '""')}"`;
}

async function snapshot(client) {
  const counts = {};
  for (const tabela of TABELAS_LIMPAR) {
    const r = await client.query(`SELECT COUNT(*)::int AS total FROM ${quoteTableName(tabela)}`);
    counts[tabela] = r.rows[0].total;
  }

  const produtos = await client.query(`
    SELECT
      COUNT(*)::int AS total,
      COALESCE(SUM(est), 0)::int AS estoque_total,
      COUNT(*) FILTER (WHERE COALESCE(est, 0) <> 0)::int AS com_estoque
    FROM produtos
  `);
  counts.produtos = produtos.rows[0];
  return counts;
}

async function main() {
  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
  });

  await client.connect();
  const before = await snapshot(client);

  await client.query('BEGIN');
  try {
    await client.query(
      `TRUNCATE TABLE ${TABELAS_LIMPAR.map(quoteTableName).join(', ')} RESTART IDENTITY CASCADE`
    );
    await client.query(`UPDATE produtos SET est=0, atualizado_em=NOW()`);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  }

  const after = await snapshot(client);
  await client.end();

  process.stdout.write(JSON.stringify({
    ok: true,
    action: 'reset-operacao-producao',
    cleanedTables: TABELAS_LIMPAR,
    before,
    after
  }, null, 2));
}

main().catch(async err => {
  console.error(err.stack || err.message || String(err));
  process.exit(1);
});
