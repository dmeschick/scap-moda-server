const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const SALT_ROUNDS = 10;
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();
const crypto = require('crypto');
const { Resend } = require('resend');
const resend = new Resend(process.env.RESEND_API_KEY);

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// Rate limiting
const limiterGeral = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { erro: 'Muitas requisições. Tente novamente em 15 minutos.' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiterGeral);

const limiterLogin = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { erro: 'Muitas tentativas de login. Tente novamente em 15 minutos.' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/login', limiterLogin);
app.use('/api/auth/validar-senha', limiterLogin);
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});
app.use(express.static('public'));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20
});

const JWT_SECRET = process.env.JWT_SECRET || 'scap-moda-secret-2024';
const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2,6);
const tokenBlacklist = new Set();

async function registrarMovimento(client, { produtoId, produtoNome, produtoCod, tipo, quantidade, estoqueAnterior, estoquePosteriror, motivo, vendaId, usuarioId, usuarioNome }) {
  await client.query(
    `INSERT INTO estoque_movimentos
     (id, produto_id, produto_nome, produto_cod, tipo, quantidade, estoque_anterior, estoque_posterior, motivo, venda_id, usuario_id, usuario_nome)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
    [uid(), produtoId, produtoNome||'', produtoCod||'', tipo, quantidade, estoqueAnterior||0, estoquePosteriror||0, motivo||'', vendaId||null, usuarioId||null, usuarioNome||'']
  );
}

function criptografarBackup(jsonStr) {
  const BACKUP_SECRET = process.env.BACKUP_SECRET || 'scap-moda-backup-2024';
  const key = crypto.scryptSync(BACKUP_SECRET, 'salt', 32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(jsonStr, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '') || req.query.token;
  if (!token) return res.status(401).json({ erro: 'Não autorizado' });
  if (tokenBlacklist.has(token)) return res.status(401).json({ erro: 'Sessão encerrada. Faça login novamente.' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ erro: 'Token inválido' }); }
}

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS funcionarios (
      id VARCHAR(50) PRIMARY KEY,
      nome VARCHAR(200) NOT NULL,
      cpf VARCHAR(20),
      cargo VARCHAR(100),
      tel VARCHAR(20),
      salario DECIMAL(10,2) DEFAULT 0,
      comissao DECIMAL(5,2) DEFAULT 0,
      admissao DATE,
      turno VARCHAR(100),
      obs TEXT,
      senha_hash VARCHAR(200),
      status VARCHAR(20) DEFAULT 'ativo',
      criado_em TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS categorias (
      id VARCHAR(50) PRIMARY KEY,
      nome VARCHAR(100) NOT NULL UNIQUE,
      descricao TEXT,
      ordem INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS fornecedores (
      id VARCHAR(50) PRIMARY KEY,
      nome VARCHAR(200) NOT NULL,
      cnpj VARCHAR(20),
      contato VARCHAR(100),
      tel VARCHAR(20),
      email VARCHAR(100),
      cidade VARCHAR(100),
      cats VARCHAR(200),
      prazo VARCHAR(100),
      pgto VARCHAR(100),
      site VARCHAR(200),
      obs TEXT,
      status VARCHAR(20) DEFAULT 'ativo'
    );
    CREATE TABLE IF NOT EXISTS produtos (
      id VARCHAR(50) PRIMARY KEY,
      cod VARCHAR(50) UNIQUE NOT NULL,
      nome VARCHAR(200) NOT NULL,
      cat VARCHAR(100),
      cor VARCHAR(100),
      tam VARCHAR(100),
      colecao VARCHAR(100),
      custo DECIMAL(10,2) DEFAULT 0,
      venda DECIMAL(10,2) DEFAULT 0,
      est INTEGER DEFAULT 0,
      estmin INTEGER DEFAULT 5,
      descricao TEXT,
      foto TEXT,
      forn VARCHAR(50),
      ncm VARCHAR(20),
      cest VARCHAR(20),
      cfop VARCHAR(10) DEFAULT '5102',
      csosn VARCHAR(10) DEFAULT '400',
      origem VARCHAR(5) DEFAULT '0',
      unidade VARCHAR(10) DEFAULT 'UN',
      cst_pis VARCHAR(10) DEFAULT '07',
      cst_cofins VARCHAR(10) DEFAULT '07',
      status VARCHAR(20) DEFAULT 'ativo',
      atualizado_em TIMESTAMP DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_produtos_cod ON produtos(cod);
    CREATE INDEX IF NOT EXISTS idx_produtos_nome ON produtos(LOWER(nome));
    CREATE INDEX IF NOT EXISTS idx_produtos_cat ON produtos(cat);
    CREATE TABLE IF NOT EXISTS clientes (
      id VARCHAR(50) PRIMARY KEY,
      nome VARCHAR(200) NOT NULL,
      tipo VARCHAR(5) DEFAULT 'PF',
      cpf VARCHAR(20),
      cnpj VARCHAR(20),
      nasc DATE,
      tel VARCHAR(20),
      email VARCHAR(100),
      ig VARCHAR(100),
      tam VARCHAR(50),
      obs TEXT,
      total_compras DECIMAL(10,2) DEFAULT 0,
      ult_compra DATE,
      status VARCHAR(20) DEFAULT 'ativo'
    );
    CREATE INDEX IF NOT EXISTS idx_clientes_nome ON clientes(LOWER(nome));
    CREATE TABLE IF NOT EXISTS vendas (
      id VARCHAR(50) PRIMARY KEY,
      num VARCHAR(20),
      data TIMESTAMP DEFAULT NOW(),
      cliente_id VARCHAR(50),
      cliente_nome VARCHAR(200),
      vendedor_id VARCHAR(50),
      vendedor_nome VARCHAR(200),
      canal VARCHAR(20) DEFAULT 'presencial',
      subtotal DECIMAL(10,2) DEFAULT 0,
      desconto DECIMAL(10,2) DEFAULT 0,
      credito DECIMAL(10,2) DEFAULT 0,
      tot DECIMAL(10,2) DEFAULT 0,
      pag VARCHAR(200),
      obs TEXT,
      tipo VARCHAR(20) DEFAULT 'venda',
      status VARCHAR(20) DEFAULT 'pago',
      cancelada_em TIMESTAMP,
      criado_em TIMESTAMP DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_vendas_data ON vendas(data);
    CREATE TABLE IF NOT EXISTS venda_itens (
      id SERIAL PRIMARY KEY,
      venda_id VARCHAR(50) REFERENCES vendas(id) ON DELETE CASCADE,
      produto_id VARCHAR(50),
      nome VARCHAR(200),
      cod VARCHAR(50),
      preco DECIMAL(10,2),
      qty INTEGER,
      tipo VARCHAR(20) DEFAULT 'novo'
    );
    CREATE TABLE IF NOT EXISTS venda_pagamentos (
      id SERIAL PRIMARY KEY,
      venda_id VARCHAR(50) REFERENCES vendas(id) ON DELETE CASCADE,
      tipo VARCHAR(50),
      valor DECIMAL(10,2),
      parcelas INTEGER DEFAULT 1,
      vl_parcela DECIMAL(10,2),
      troco DECIMAL(10,2) DEFAULT 0,
      detalhe VARCHAR(200),
      cheques_json JSONB DEFAULT '[]'
    );
    CREATE TABLE IF NOT EXISTS configuracoes (
      chave VARCHAR(100) PRIMARY KEY,
      valor JSONB,
      atualizado_em TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS enderecos_cliente (
      id VARCHAR(50) PRIMARY KEY,
      cliente_id VARCHAR(50) REFERENCES clientes(id) ON DELETE CASCADE,
      tipo VARCHAR(50) DEFAULT 'Residencial',
      cep VARCHAR(10),
      logradouro VARCHAR(200),
      numero VARCHAR(20),
      complemento VARCHAR(100),
      bairro VARCHAR(100),
      cidade VARCHAR(100),
      estado VARCHAR(2),
      principal BOOLEAN DEFAULT false
    );
    CREATE INDEX IF NOT EXISTS idx_end_cliente ON enderecos_cliente(cliente_id);
    CREATE TABLE IF NOT EXISTS ponto (
      id SERIAL PRIMARY KEY,
      funcionario_id VARCHAR(50) NOT NULL,
      funcionario_nome VARCHAR(200),
      data DATE NOT NULL,
      tipo VARCHAR(30) NOT NULL,
      horario TIMESTAMP DEFAULT NOW(),
      obs TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_ponto_func ON ponto(funcionario_id);
    CREATE INDEX IF NOT EXISTS idx_ponto_data ON ponto(data);
    ALTER TABLE funcionarios ADD COLUMN IF NOT EXISTS foto TEXT;
    ALTER TABLE venda_pagamentos ADD COLUMN IF NOT EXISTS cheques_json JSONB DEFAULT '[]';
    CREATE TABLE IF NOT EXISTS metas_comissao (
      id TEXT PRIMARY KEY,
      mes TEXT NOT NULL UNIQUE,
      faixa2 NUMERIC(10,2) NOT NULL,
      faixa3 NUMERIC(10,2) NOT NULL,
      faixa4 NUMERIC(10,2) NOT NULL,
      criado_em TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS contas_pagar (
      id TEXT PRIMARY KEY,
      descricao TEXT NOT NULL,
      categoria TEXT NOT NULL,
      valor NUMERIC(10,2) NOT NULL,
      vencimento DATE NOT NULL,
      pago BOOLEAN DEFAULT FALSE,
      data_pagamento DATE,
      valor_pago NUMERIC(10,2),
      forma_pagamento TEXT,
      observacao TEXT,
      recorrente BOOLEAN DEFAULT FALSE,
      criado_em TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS cheques (
      id TEXT PRIMARY KEY,
      tipo TEXT NOT NULL,
      valor NUMERIC(10,2) NOT NULL,
      data_cheque DATE NOT NULL,
      data_compensacao DATE NOT NULL,
      nome TEXT NOT NULL,
      banco TEXT,
      numero TEXT,
      status TEXT DEFAULT 'pendente',
      cliente_id TEXT,
      observacao TEXT,
      criado_em TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS caixa (
      id TEXT PRIMARY KEY,
      data DATE NOT NULL UNIQUE,
      valor_abertura NUMERIC(10,2) NOT NULL,
      valor_fechamento NUMERIC(10,2),
      valor_sistema NUMERIC(10,2),
      diferenca NUMERIC(10,2),
      status TEXT DEFAULT 'aberto',
      observacao TEXT,
      criado_em TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS caixa_movimentos (
      id TEXT PRIMARY KEY,
      caixa_id TEXT NOT NULL,
      tipo TEXT NOT NULL,
      descricao TEXT NOT NULL,
      valor NUMERIC(10,2) NOT NULL,
      categoria TEXT,
      referencia_id TEXT,
      referencia_tipo TEXT,
      criado_em TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS creditos_clientes (
      id TEXT PRIMARY KEY,
      cliente_id TEXT NOT NULL,
      cliente_nome TEXT,
      valor NUMERIC(10,2) NOT NULL,
      valor_usado NUMERIC(10,2) DEFAULT 0,
      motivo TEXT,
      venda_id TEXT,
      status TEXT DEFAULT 'ativo',
      criado_em TIMESTAMP DEFAULT NOW()
    );
    CREATE SEQUENCE IF NOT EXISTS venda_num_seq START 1;
  `);
  // Remove vendas duplicadas por número (mantém a mais antiga) antes de criar índice único
  await pool.query(`
    DELETE FROM vendas WHERE id NOT IN (
      SELECT DISTINCT ON (num) id FROM vendas ORDER BY num, data ASC
    )
  `);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_vendas_num ON vendas(num)`);
  // Adiciona colunas que podem não existir em bancos criados antes dessas definições
  await pool.query(`ALTER TABLE clientes ADD COLUMN IF NOT EXISTS criado_em TIMESTAMP DEFAULT NOW()`);
  await pool.query(`ALTER TABLE vendas ADD COLUMN IF NOT EXISTS credito_gerado NUMERIC(10,2) DEFAULT 0`);
  await pool.query(`ALTER TABLE vendas ADD COLUMN IF NOT EXISTS desc_pct NUMERIC(5,2) DEFAULT 0`);
  await pool.query(`ALTER TABLE categorias ADD COLUMN IF NOT EXISTS sufixo TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE produtos ADD COLUMN IF NOT EXISTS criado_em TIMESTAMP DEFAULT NOW()`);
  await pool.query(`CREATE TABLE IF NOT EXISTS auditoria (
    id TEXT PRIMARY KEY,
    usuario_id TEXT NOT NULL,
    usuario_nome TEXT,
    cargo TEXT,
    acao TEXT NOT NULL,
    detalhes TEXT,
    ip TEXT,
    criado_em TIMESTAMP DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS estoque_movimentos (
    id TEXT PRIMARY KEY,
    produto_id TEXT NOT NULL,
    produto_nome TEXT,
    produto_cod TEXT,
    tipo TEXT NOT NULL,
    quantidade INTEGER NOT NULL,
    estoque_anterior INTEGER,
    estoque_posterior INTEGER,
    motivo TEXT,
    venda_id TEXT,
    usuario_id TEXT,
    usuario_nome TEXT,
    criado_em TIMESTAMP DEFAULT NOW()
  )`);
  await pool.query(`
    SELECT SETVAL('venda_num_seq',
      COALESCE(
        (SELECT MAX(CAST(REPLACE(num, '#', '') AS INTEGER)) FROM vendas WHERE num ~ '^#[0-9]+$'),
        0
      )
    );
  `);
  console.log('Banco inicializado!');
}

// LOGIN
app.post('/api/login', async (req, res) => {
  try {
    const { funcId, senha } = req.body;
    const r = await pool.query('SELECT * FROM funcionarios WHERE id=$1 AND status=$2', [funcId, 'ativo']);
    if (!r.rows.length) return res.status(401).json({ erro: 'Funcionário não encontrado' });
    const func = r.rows[0];
    let senhaValida = false;
    if (func.senha_hash && func.senha_hash.startsWith('$2b$')) {
      senhaValida = await bcrypt.compare(senha, func.senha_hash);
    } else {
      const cpfDigitos = (func.cpf || '').replace(/\D/g, '');
      const senhaPadrao = cpfDigitos.length >= 4 ? cpfDigitos.slice(0, 4) : '1234';
      senhaValida = senha === senhaPadrao;
      if (senhaValida) {
        const hash = await bcrypt.hash(senha, SALT_ROUNDS);
        await pool.query('UPDATE funcionarios SET senha_hash=$1 WHERE id=$2', [hash, func.id]);
      }
    }
    if (!senhaValida) return res.status(401).json({ erro: 'Senha incorreta' });
    const token = jwt.sign({ id: func.id, nome: func.nome, cargo: func.cargo }, JWT_SECRET, { expiresIn: '10h' });
    res.json({ token, funcionario: { id: func.id, nome: func.nome, cargo: func.cargo } });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// Logout — invalidar token
app.post('/api/logout', auth, (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (token) tokenBlacklist.add(token);
  res.json({ ok: true });
});

// AUTH — Validar senha do próprio usuário
app.post('/api/auth/validar-senha', auth, async (req, res) => {
  try {
    const { senha } = req.body;
    const usuario = req.user;
    const r = await pool.query('SELECT * FROM funcionarios WHERE id=$1', [usuario.id]);
    if (!r.rows.length) return res.status(401).json({ ok: false, erro: 'Usuário não encontrado' });
    const func = r.rows[0];
    let senhaCorreta = false;
    if (func.senha_hash && func.senha_hash.startsWith('$2b$')) {
      senhaCorreta = await bcrypt.compare(senha, func.senha_hash);
    } else {
      const cpfDigitos = (func.cpf || '').replace(/\D/g, '');
      const senhaPadrao = cpfDigitos.length >= 4 ? cpfDigitos.slice(0, 4) : '1234';
      senhaCorreta = senha === senhaPadrao;
      if (senhaCorreta) {
        const hash = await bcrypt.hash(senha, SALT_ROUNDS);
        await pool.query('UPDATE funcionarios SET senha_hash=$1 WHERE id=$2', [hash, func.id]);
      }
    }
    if (!senhaCorreta) return res.json({ ok: false, erro: 'Senha incorreta' });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// AUDITORIA — Registrar
app.post('/api/auditoria', auth, async (req, res) => {
  try {
    const { acao, detalhes } = req.body;
    const usuario = req.user;
    await pool.query(
      `INSERT INTO auditoria (id, usuario_id, usuario_nome, cargo, acao, detalhes, ip)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [uid(), usuario.id, usuario.nome, usuario.cargo, acao, detalhes || '', req.ip || '']
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// AUDITORIA — Buscar log
app.get('/api/auditoria', auth, async (req, res) => {
  try {
    const r = await pool.query(`SELECT * FROM auditoria ORDER BY criado_em DESC LIMIT 200`);
    res.json(r.rows);
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// FUNCIONÁRIOS
app.get('/api/funcionarios', async (req, res) => {
  try {
    const { todos, login } = req.query;
    let sql;
    if (login) {
      sql = "SELECT id,nome,cpf,cargo,tel,salario,comissao,admissao,turno,obs,status,foto FROM funcionarios WHERE cargo IN ('Administrador','Gerente') AND status='ativo' ORDER BY nome";
    } else if (todos) {
      sql = 'SELECT id,nome,cpf,cargo,tel,salario,comissao,admissao,turno,obs,status,foto FROM funcionarios ORDER BY nome';
    } else {
      sql = "SELECT id,nome,cpf,cargo,tel,salario,comissao,admissao,turno,obs,status,foto FROM funcionarios WHERE status='ativo' ORDER BY nome";
    }
    const r = await pool.query(sql);
    res.json(r.rows);
  } catch (err) { res.status(500).json({ erro: err.message }); }
});
app.delete('/api/funcionarios/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM funcionarios WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});
app.post('/api/funcionarios', auth, async (req, res) => {
  try {
    const f = req.body;
    // foto='' significa remover, foto=null significa manter a atual
    const fotoVal = f.foto === '' ? null : f.foto;
    const fotoUpdate = f.foto === undefined ? 'funcionarios.foto' : '$12';
    await pool.query(`INSERT INTO funcionarios (id,nome,cpf,cargo,tel,salario,comissao,admissao,turno,obs,status,foto)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
      ON CONFLICT (id) DO UPDATE SET nome=$2,cpf=$3,cargo=$4,tel=$5,salario=$6,comissao=$7,admissao=$8,turno=$9,obs=$10,status=$11,foto=${fotoUpdate}`,
      [f.id,f.nome,f.cpf,f.cargo,f.tel,f.salario||0,f.comissao||0,f.admissao||null,f.turno,f.obs,f.status||'ativo',fotoVal]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});
app.put('/api/funcionarios/:id/senha', auth, async (req, res) => {
  try {
    const hash = await bcrypt.hash(req.body.senha, SALT_ROUNDS);
    await pool.query('UPDATE funcionarios SET senha_hash=$1 WHERE id=$2', [hash, req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// CATEGORIAS
app.get('/api/categorias', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM categorias ORDER BY ordem,nome');
    res.json(r.rows);
  } catch (err) { res.status(500).json({ erro: err.message }); }
});
app.post('/api/categorias', auth, async (req, res) => {
  try {
    const c = req.body;
    await pool.query(`INSERT INTO categorias (id,nome,descricao,ordem) VALUES ($1,$2,$3,$4)
      ON CONFLICT (id) DO UPDATE SET nome=$2,descricao=$3,ordem=$4`,
      [c.id,c.nome,c.descricao||'',c.ordem||0]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});
app.delete('/api/categorias/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM categorias WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// CATEGORIAS

// FORNECEDORES
app.get('/api/fornecedores', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM fornecedores ORDER BY nome');
    res.json(r.rows);
  } catch (err) { res.status(500).json({ erro: err.message }); }
});
app.post('/api/fornecedores', auth, async (req, res) => {
  try {
    const f = req.body;
    await pool.query(`INSERT INTO fornecedores (id,nome,cnpj,contato,tel,email,cidade,cats,prazo,pgto,site,obs,status)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
      ON CONFLICT (id) DO UPDATE SET nome=$2,cnpj=$3,contato=$4,tel=$5,email=$6,cidade=$7,cats=$8,prazo=$9,pgto=$10,site=$11,obs=$12,status=$13`,
      [f.id,f.nome,f.cnpj,f.contato,f.tel,f.email,f.cidade,f.cats,f.prazo,f.pgto,f.site,f.obs,f.status||'ativo']);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});
app.delete('/api/fornecedores/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM fornecedores WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// PRODUTOS
app.get('/api/produtos', auth, async (req, res) => {
  try {
    const { q, cat, status, limit, offset } = req.query;
    let where = [];
    let params = [];
    let i = 1;
    where.push(`status=${status ? `$${i++}` : "'ativo'"}`);
    if (status) params.push(status);
    if (cat) { where.push(`cat=$${i++}`); params.push(cat); }
    if (q) { where.push(`(LOWER(nome) LIKE $${i} OR cod ILIKE $${i})`); params.push('%'+q.toLowerCase()+'%'); i++; }
    const sql = `SELECT * FROM produtos WHERE ${where.join(' AND ')} ORDER BY criado_em DESC LIMIT ${parseInt(limit)||500} OFFSET ${parseInt(offset)||0}`;
    const r = await pool.query(sql, params);
    res.json(r.rows);
  } catch (err) { res.status(500).json({ erro: err.message }); }
});
app.post('/api/produtos', auth, async (req, res) => {
  try {
    const p = req.body;
    await pool.query(`INSERT INTO produtos (id,cod,nome,cat,cor,tam,colecao,custo,venda,est,estmin,descricao,foto,forn,ncm,cest,cfop,csosn,origem,unidade,cst_pis,cst_cofins,status,atualizado_em)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,NOW())
      ON CONFLICT (id) DO UPDATE SET cod=$2,nome=$3,cat=$4,cor=$5,tam=$6,colecao=$7,custo=$8,venda=$9,est=$10,estmin=$11,descricao=$12,foto=$13,forn=$14,ncm=$15,cest=$16,cfop=$17,csosn=$18,origem=$19,unidade=$20,cst_pis=$21,cst_cofins=$22,status=$23,atualizado_em=NOW()`,
      [p.id,p.cod,p.nome,p.cat,p.cor,p.tam,p.colecao,p.custo||0,p.venda||0,p.est||0,p.estmin||5,p.descricao||p.desc,p.foto,p.forn,p.ncm,p.cest,p.cfop||'5102',p.csosn||'400',p.origem||'0',p.unidade||'UN',p.cstPis||'07',p.cstCofins||'07',p.status||'ativo']);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});
app.delete('/api/produtos/:id', auth, async (req, res) => {
  try {
    await pool.query("UPDATE produtos SET status='inativo' WHERE id=$1", [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});
// PRODUTOS — Próximo código por categoria
app.get('/api/produtos/proximo-codigo', auth, async (req, res) => {
  try {
    const { categoriaId } = req.query;
    if (!categoriaId) return res.status(400).json({ erro: 'Informe a categoria' });

    // Busca sufixo da categoria (categoriaId recebe o nome, pois o select usa value=nome)
    const cat = await pool.query('SELECT nome, sufixo FROM categorias WHERE nome=$1', [categoriaId]);
    if (!cat.rows.length) return res.status(404).json({ erro: 'Categoria não encontrada' });

    // Mapeamento fixo de sufixos
    const sufixosFixos = {
      'blusa': 'B', 'blusas': 'B',
      'vestido': 'V', 'vestidos': 'V',
      'calca': 'C', 'calcas': 'C',
      'conjunto': 'U', 'conjuntos': 'U',
      'saia': 'S', 'saias': 'S',
      'acessorio': 'A', 'acessorios': 'A',
      'short': 'H', 'shorts': 'H',
      'macacao': 'M', 'macacoes': 'M'
    };

    const nomeNorm = cat.rows[0].nome.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    const sufixo = cat.rows[0].sufixo || sufixosFixos[nomeNorm] || cat.rows[0].nome.charAt(0).toUpperCase();

    // Busca último código desta categoria
    const r = await pool.query(
      `SELECT cod FROM produtos WHERE cod LIKE $1 ORDER BY cod DESC LIMIT 1`,
      ['%' + sufixo]
    );

    let proximoNum = 1;
    if (r.rows.length) {
      const ultimoCod = r.rows[0].cod;
      const num = parseInt(ultimoCod.replace(sufixo, '')) || 0;
      proximoNum = num + 1;
    }

    const novoCod = String(proximoNum).padStart(6, '0') + sufixo;
    res.json({ cod: novoCod, sufixo });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// ESTOQUE — Histórico de movimentações
app.get('/api/estoque/movimentos', auth, async (req, res) => {
  try {
    const { produtoId, tipo, dataInicio, dataFim, limit } = req.query;
    let where = 'WHERE 1=1';
    const params = [];
    let i = 1;
    if (produtoId) { where += ` AND produto_id=$${i++}`; params.push(produtoId); }
    if (tipo) { where += ` AND tipo=$${i++}`; params.push(tipo); }
    if (dataInicio) { where += ` AND DATE(criado_em) >= $${i++}`; params.push(dataInicio); }
    if (dataFim) { where += ` AND DATE(criado_em) <= $${i++}`; params.push(dataFim); }
    const r = await pool.query(
      `SELECT * FROM estoque_movimentos ${where} ORDER BY criado_em DESC LIMIT $${i}`,
      [...params, parseInt(limit) || 200]
    );
    res.json(r.rows);
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// PRODUTOS — Última entrada de estoque
app.get('/api/produtos/:id/ultima-entrada', auth, async (req, res) => {
  try {
    const prod = await pool.query('SELECT est FROM produtos WHERE id=$1', [req.params.id]);
    if (!prod.rows.length) return res.status(404).json({ erro: 'Produto não encontrado' });

    let ultimaEntrada = prod.rows[0].est;

    try {
      const mov = await pool.query(
        `SELECT quantidade FROM estoque_movimentos
         WHERE produto_id=$1 AND tipo='entrada'
         ORDER BY criado_em DESC LIMIT 1`,
        [req.params.id]
      );
      if (mov.rows.length) ultimaEntrada = mov.rows[0].quantidade;
    } catch(e) {} // tabela pode não existir

    res.json({ ultimaEntrada });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.patch('/api/produtos/:id/estoque', auth, async (req, res) => {
  try {
    const { delta, motivo } = req.body;
    const prodId = req.params.id;
    const antes = await pool.query('SELECT est, nome, cod FROM produtos WHERE id=$1', [prodId]);
    const estoqueAnterior = antes.rows[0]?.est || 0;
    const produtoNome = antes.rows[0]?.nome || '';
    const produtoCod = antes.rows[0]?.cod || '';
    await pool.query('UPDATE produtos SET est=GREATEST(0,est+$1),atualizado_em=NOW() WHERE id=$2', [delta, prodId]);
    const r = await pool.query('SELECT est FROM produtos WHERE id=$1', [prodId]);
    const estoquePosteriror = r.rows[0]?.est || 0;
    await registrarMovimento(pool, {
      produtoId: prodId, produtoNome, produtoCod,
      tipo: 'ajuste', quantidade: delta,
      estoqueAnterior, estoquePosteriror,
      motivo: motivo || 'Ajuste manual',
      usuarioId: req.user?.id, usuarioNome: req.user?.nome
    });
    res.json({ est: estoquePosteriror });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});


// CLIENTES
app.get('/api/clientes', auth, async (req, res) => {
  try {
    const { q } = req.query;
    let where = ["c.status != 'inativo'"];
    let params = [];
    if (q) { where.push(`(LOWER(c.nome) LIKE $1 OR c.cpf LIKE $1 OR c.tel LIKE $1)`); params.push('%'+q.toLowerCase()+'%'); }
    const sql = `
      SELECT c.*,
        COALESCE((
          SELECT SUM(valor - valor_usado)
          FROM creditos_clientes
          WHERE cliente_id=c.id AND status='ativo'
        ), 0) as saldo_credito,
        COALESCE(json_agg(e.* ORDER BY e.principal DESC) FILTER (WHERE e.id IS NOT NULL), '[]') as enderecos
      FROM clientes c
      LEFT JOIN enderecos_cliente e ON e.cliente_id=c.id
      WHERE ${where.join(' AND ')}
      GROUP BY c.id ORDER BY c.criado_em DESC`;
    const r = await pool.query(sql, params);
    res.json(r.rows);
  } catch (err) { res.status(500).json({ erro: err.message }); }
});
app.post('/api/clientes', auth, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const c = req.body;
    await client.query(`INSERT INTO clientes (id,nome,tipo,cpf,cnpj,nasc,tel,email,ig,tam,obs,total_compras,ult_compra,status)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
      ON CONFLICT (id) DO UPDATE SET nome=$2,tipo=$3,cpf=$4,cnpj=$5,nasc=$6,tel=$7,email=$8,ig=$9,tam=$10,obs=$11,total_compras=$12,ult_compra=$13,status=$14`,
      [c.id,c.nome,c.tipo||'PF',c.cpf,c.cnpj,c.nasc||null,c.tel,c.email,c.ig,c.tam,c.obs,c.totalCompras||c.total_compras||0,c.ultCompra||c.ult_compra||null,c.status||'ativo']);
    // Salva endereços
    if (c.enderecos !== undefined) {
      await client.query('DELETE FROM enderecos_cliente WHERE cliente_id=$1', [c.id]);
      for (const e of (c.enderecos||[])) {
        await client.query(`INSERT INTO enderecos_cliente (id,cliente_id,tipo,cep,logradouro,numero,complemento,bairro,cidade,estado,principal)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
          [e.id||uid(),c.id,e.tipo||'Residencial',e.cep,e.logradouro,e.numero,e.complemento,e.bairro,e.cidade,e.estado,e.principal||false]);
      }
    }
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ erro: err.message });
  } finally { client.release(); }
});
app.delete('/api/clientes/:id', auth, async (req, res) => {
  try {
    await pool.query("DELETE FROM clientes WHERE id=$1", [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// CRÉDITOS DE CLIENTES
app.get('/api/creditos/:clienteId', auth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT * FROM creditos_clientes WHERE cliente_id=$1 AND status='ativo' ORDER BY criado_em DESC`,
      [req.params.clienteId]
    );
    const total = r.rows.reduce((a, c) => a + parseFloat(c.valor) - parseFloat(c.valor_usado), 0);
    res.json({ creditos: r.rows, total: Math.round(total * 100) / 100 });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.post('/api/creditos', auth, async (req, res) => {
  try {
    const { id, clienteId, clienteNome, valor, motivo, vendaId } = req.body;
    await pool.query(
      `INSERT INTO creditos_clientes (id, cliente_id, cliente_nome, valor, motivo, venda_id)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [id, clienteId, clienteNome, valor, motivo||'Troca', vendaId||null]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.patch('/api/creditos/:id/usar', auth, async (req, res) => {
  try {
    const { valorUsado } = req.body;
    await pool.query(
      `UPDATE creditos_clientes SET valor_usado=valor_usado+$1,
       status=CASE WHEN valor_usado+$1 >= valor THEN 'usado' ELSE 'ativo' END
       WHERE id=$2`,
      [valorUsado, req.params.id]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// VENDAS
app.get('/api/vendas', auth, async (req, res) => {
  try {
    const { de, ate, status, limit, offset } = req.query;
    let where = ['1=1'];
    let params = [];
    let i = 1;
    if (de) { where.push(`DATE(data) >= $${i++}`); params.push(de); }
    if (ate) { where.push(`DATE(data) <= $${i++}`); params.push(ate); }
    if (status) { where.push(`v.status = $${i++}`); params.push(status); }
    const sql = `
      SELECT v.*,
        COALESCE(json_agg(DISTINCT jsonb_build_object('id',vi.id,'nome',vi.nome,'cod',vi.cod,'preco',vi.preco,'qty',vi.qty,'tipo',vi.tipo)) FILTER (WHERE vi.id IS NOT NULL),'[]') as itens,
        COALESCE(json_agg(DISTINCT jsonb_build_object('tipo',vp.tipo,'valor',vp.valor,'parcelas',vp.parcelas,'vl_parcela',vp.vl_parcela,'detalhe',vp.detalhe,'cheques_json',vp.cheques_json)) FILTER (WHERE vp.id IS NOT NULL),'[]') as pgto_itens
      FROM vendas v
      LEFT JOIN venda_itens vi ON vi.venda_id=v.id
      LEFT JOIN venda_pagamentos vp ON vp.venda_id=v.id
      WHERE ${where.join(' AND ')}
      GROUP BY v.id ORDER BY v.data DESC
      LIMIT ${parseInt(limit)||200} OFFSET ${parseInt(offset)||0}`;
    const r = await pool.query(sql, params);
    res.json(r.rows);
  } catch (err) { res.status(500).json({ erro: err.message }); }
});
app.post('/api/vendas', auth, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const v = req.body;
    const insertResult = await client.query(`INSERT INTO vendas (id,num,data,cliente_id,cliente_nome,vendedor_id,vendedor_nome,canal,subtotal,desconto,desc_pct,credito,tot,credito_gerado,pag,obs,tipo,status)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
      ON CONFLICT (id) DO NOTHING RETURNING id`,
      [v.id,v.num,v.data,v.clienteId,v.clienteNome,v.vendedorId,v.vendedorNome,v.canal,v.sub||v.subtotal,v.desc||v.desconto||0,v.descPct||v.desc_pct||0,v.credito||0,v.tot,v.creditoGerado||0,v.pag,v.obs,v.tipo||'venda',v.status||'pago']);
    if (insertResult.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.json({ ok: true, duplicata: true });
    }
    for (const item of (v.itens||[])) {
      await client.query('INSERT INTO venda_itens (venda_id,produto_id,nome,cod,preco,qty,tipo) VALUES ($1,$2,$3,$4,$5,$6,$7)',
        [v.id,item.id,item.nome,item.cod,item.preco,item.qty,item.tipo||'novo']);
      const estAntes = await client.query('SELECT est FROM produtos WHERE id=$1', [item.id]);
      const estoqueAnterior = estAntes.rows[0]?.est || 0;
      if (item.tipo === 'devolvido') {
        await client.query('UPDATE produtos SET est=est+$1,atualizado_em=NOW() WHERE id=$2', [item.qty, item.id]);
        await registrarMovimento(client, {
          produtoId: item.id, produtoNome: item.nome, produtoCod: item.cod,
          tipo: 'devolucao', quantidade: item.qty,
          estoqueAnterior, estoquePosteriror: estoqueAnterior + item.qty,
          motivo: 'Devolução venda ' + v.num, vendaId: v.id,
          usuarioId: v.vendedorId, usuarioNome: v.vendedorNome
        });
      } else {
        await client.query('UPDATE produtos SET est=GREATEST(0,est-$1),atualizado_em=NOW() WHERE id=$2', [item.qty, item.id]);
        const estoquePos = Math.max(0, estoqueAnterior - item.qty);
        await registrarMovimento(client, {
          produtoId: item.id, produtoNome: item.nome, produtoCod: item.cod,
          tipo: 'venda', quantidade: item.qty,
          estoqueAnterior, estoquePosteriror: estoquePos,
          motivo: 'Venda ' + v.num, vendaId: v.id,
          usuarioId: v.vendedorId, usuarioNome: v.vendedorNome
        });
      }
    }
    for (const p of (v.pgtoItens||[])) {
      await client.query('INSERT INTO venda_pagamentos (venda_id,tipo,valor,parcelas,vl_parcela,troco,detalhe,cheques_json) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
        [v.id,p.tipo,p.valor,p.parcelas||1,p.vlParcela||p.valor,p.troco||0,p.detalhe||'',JSON.stringify(p.cheques||[])]);
    }
    if (v.clienteId) {
      await client.query('UPDATE clientes SET total_compras=total_compras+$1,ult_compra=CURRENT_DATE WHERE id=$2', [v.tot, v.clienteId]);
    }
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ erro: err.message });
  } finally { client.release(); }
});
app.patch('/api/vendas/:id/cancelar', auth, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const r = await client.query('SELECT * FROM vendas WHERE id=$1', [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ erro: 'Venda não encontrada' });
    const venda = r.rows[0];
    await client.query("UPDATE vendas SET status='cancelada',cancelada_em=NOW() WHERE id=$1", [req.params.id]);
    const itens = await client.query('SELECT * FROM venda_itens WHERE venda_id=$1 AND tipo!=\'devolvido\'', [req.params.id]);
    for (const item of itens.rows) {
      await client.query('UPDATE produtos SET est=est+$1,atualizado_em=NOW() WHERE id=$2', [item.qty, item.produto_id]);
    }
    if (venda.cliente_id) {
      await client.query('UPDATE clientes SET total_compras=GREATEST(0,total_compras-$1) WHERE id=$2', [venda.tot, venda.cliente_id]);
    }
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ erro: err.message });
  } finally { client.release(); }
});

// CONFIGURAÇÕES
app.get('/api/config/:chave', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT valor FROM configuracoes WHERE chave=$1', [req.params.chave]);
    res.json({ valor: r.rows[0]?.valor || null });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});
app.post('/api/config/:chave', auth, async (req, res) => {
  try {
    await pool.query(`INSERT INTO configuracoes (chave,valor,atualizado_em) VALUES ($1,$2,NOW()) ON CONFLICT (chave) DO UPDATE SET valor=$2,atualizado_em=NOW()`,
      [req.params.chave, JSON.stringify(req.body.valor)]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// RELATÓRIOS
app.get('/api/relatorios/mensal', auth, async (req, res) => {
  try {
    const { mes } = req.query;
    const [resumo, porDia, porVendedor, topProdutos] = await Promise.all([
      pool.query(`SELECT COUNT(*) as total_vendas,
        COALESCE(SUM(tot + COALESCE(credito_gerado,0)),0) as faturamento,
        AVG(tot + COALESCE(credito_gerado,0)) as ticket_medio,
        COUNT(*) FILTER (WHERE canal='presencial') as presencial,COUNT(*) FILTER (WHERE canal='online') as online,
        COALESCE(SUM(CASE WHEN canal='presencial' AND status='pago' THEN tot + COALESCE(credito_gerado,0) END),0) as valor_presencial,
        COALESCE(SUM(CASE WHEN canal='online' AND status='pago' THEN tot + COALESCE(credito_gerado,0) END),0) as valor_online
        FROM vendas WHERE TO_CHAR(data,'YYYY-MM')=$1 AND status!='cancelada'`, [mes]),
      pool.query(`SELECT DATE(data) as dia,SUM(tot) as total,COUNT(*) as qtd FROM vendas
        WHERE TO_CHAR(data,'YYYY-MM')=$1 AND status!='cancelada' GROUP BY DATE(data) ORDER BY dia`, [mes]),
      pool.query(`SELECT vendedor_nome,COUNT(*) as qtd,SUM(tot) as total FROM vendas
        WHERE TO_CHAR(data,'YYYY-MM')=$1 AND status!='cancelada' GROUP BY vendedor_nome ORDER BY total DESC`, [mes]),
      pool.query(`SELECT vi.nome,SUM(vi.qty) as qty,SUM(vi.preco*vi.qty) as receita FROM venda_itens vi
        JOIN vendas v ON v.id=vi.venda_id WHERE TO_CHAR(v.data,'YYYY-MM')=$1 AND v.status!='cancelada' AND vi.tipo!='devolvido'
        GROUP BY vi.nome ORDER BY qty DESC LIMIT 20`, [mes])
    ]);
    res.json({ resumo: resumo.rows[0], porDia: porDia.rows, porVendedor: porVendedor.rows, topProdutos: topProdutos.rows });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

const PORT = process.env.PORT || 3000;

// PONTO
app.get('/api/ponto', auth, async (req, res) => {
  try {
    const { funcId, de, ate } = req.query;
    let where = ['1=1'];
    let params = [];
    let i = 1;
    if (funcId) { where.push(`funcionario_id=$${i++}`); params.push(funcId); }
    if (de) { where.push(`data>=$${i++}`); params.push(de); }
    if (ate) { where.push(`data<=$${i++}`); params.push(ate); }
    const r = await pool.query(`SELECT * FROM ponto WHERE ${where.join(' AND ')} ORDER BY horario DESC`, params);
    res.json(r.rows);
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.post('/api/ponto', auth, async (req, res) => {
  try {
    const { funcionarioId, funcionarioNome, tipo, obs } = req.body;
    const now = new Date();
    const data = now.toISOString().split('T')[0];
    // Verifica se já existe registro do mesmo tipo hoje
    const existe = await pool.query(
      'SELECT id FROM ponto WHERE funcionario_id=$1 AND data=$2 AND tipo=$3',
      [funcionarioId, data, tipo]
    );
    if (existe.rows.length) return res.status(400).json({ erro: `Registro de "${tipo}" já feito hoje` });
    await pool.query(
      'INSERT INTO ponto (funcionario_id,funcionario_nome,data,tipo,horario,obs) VALUES ($1,$2,$3,$4,$5,$6)',
      [funcionarioId, funcionarioNome, data, tipo, now, obs||'']
    );
    res.json({ ok: true, horario: now });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.get('/api/ponto/hoje', auth, async (req, res) => {
  try {
    const hoje = new Date().toISOString().split('T')[0];
    const r = await pool.query(
      'SELECT * FROM ponto WHERE funcionario_id=$1 AND data=$2 ORDER BY horario',
      [req.query.funcId, hoje]
    );
    res.json(r.rows);
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// SENHA FUNCIONÁRIO
app.put('/api/funcionarios/:id/senha', auth, async (req, res) => {
  try {
    const hash = await bcrypt.hash(req.body.senha, SALT_ROUNDS);
    await pool.query('UPDATE funcionarios SET senha_hash=$1 WHERE id=$2', [hash, req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// FOTO FUNCIONÁRIO
app.put('/api/funcionarios/:id/foto', auth, async (req, res) => {
  try {
    await pool.query('UPDATE funcionarios SET foto=$1 WHERE id=$2', [req.body.foto, req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});






















// COMISSÕES — METAS
app.get('/api/comissoes/metas', auth, async (req, res) => {
  try {
    const r = await pool.query(`SELECT * FROM metas_comissao ORDER BY mes DESC`);
    res.json(r.rows);
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.post('/api/comissoes/metas', auth, async (req, res) => {
  try {
    const { id, mes, faixa2, faixa3, faixa4 } = req.body;
    await pool.query(
      `INSERT INTO metas_comissao (id, mes, faixa2, faixa3, faixa4)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (mes) DO UPDATE SET faixa2=$3, faixa3=$4, faixa4=$5`,
      [id, mes, faixa2, faixa3, faixa4]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.delete('/api/comissoes/metas/:mes', auth, async (req, res) => {
  try {
    await pool.query(`DELETE FROM metas_comissao WHERE mes=$1`, [req.params.mes]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// COMISSÕES — CÁLCULO DO MÊS
app.get('/api/comissoes/calcular', auth, async (req, res) => {
  try {
    const { mes } = req.query;
    if (!mes) return res.status(400).json({ erro: 'Informe o mês' });

    const metaRes = await pool.query(
      `SELECT * FROM metas_comissao WHERE mes=$1`, [mes]
    );
    const meta = metaRes.rows[0] || null;

    const vendas = await pool.query(
      `SELECT v.vendedor_id, f.nome as vendedor_nome,
              COALESCE(SUM(v.tot), 0) as total_vendido,
              COUNT(*) as qtd_vendas
       FROM vendas v
       JOIN funcionarios f ON f.id = v.vendedor_id
       WHERE TO_CHAR(v.data, 'YYYY-MM') = $1
         AND v.status = 'pago'
         AND v.vendedor_id IS NOT NULL
       GROUP BY v.vendedor_id, f.nome
       ORDER BY total_vendido DESC`,
      [mes]
    );

    const resultado = vendas.rows.map(v => {
      const total = parseFloat(v.total_vendido);
      let pct = 2.0;
      let faixa = 'Base';

      if (meta) {
        if (total >= parseFloat(meta.faixa4)) { pct = 3.3; faixa = 'Faixa 4'; }
        else if (total >= parseFloat(meta.faixa3)) { pct = 2.8; faixa = 'Faixa 3'; }
        else if (total >= parseFloat(meta.faixa2)) { pct = 2.3; faixa = 'Faixa 2'; }
      }

      const comissao = Math.round(total * pct / 100 * 100) / 100;

      return {
        vendedorId: v.vendedor_id,
        vendedorNome: v.vendedor_nome,
        totalVendido: total,
        qtdVendas: parseInt(v.qtd_vendas),
        faixa,
        pct,
        comissao
      };
    });

    res.json({
      mes,
      meta: meta || null,
      vendedoras: resultado,
      totalComissoes: resultado.reduce((a, v) => a + v.comissao, 0)
    });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// FINANCEIRO — PROJEÇÃO 30 DIAS
app.get('/api/financeiro/projecao', auth, async (req, res) => {
  try {
    const hoje = new Date().toISOString().split('T')[0];
    const em30 = new Date(Date.now() + 30*24*60*60*1000).toISOString().split('T')[0];

    // Contas a vencer
    const contas = await pool.query(
      `SELECT id, descricao, categoria, valor, vencimento
       FROM contas_pagar
       WHERE pago=FALSE AND vencimento BETWEEN $1 AND $2
       ORDER BY vencimento`,
      [hoje, em30]
    );

    // Cheques a compensar (recebidos)
    const chequesEntrada = await pool.query(
      `SELECT id, nome, valor, data_compensacao
       FROM cheques
       WHERE tipo='recebido' AND status='pendente' AND data_compensacao BETWEEN $1 AND $2
       ORDER BY data_compensacao`,
      [hoje, em30]
    );

    // Cheques a compensar (emitidos)
    const chequesSaida = await pool.query(
      `SELECT id, nome, valor, data_compensacao
       FROM cheques
       WHERE tipo='emitido' AND status='pendente' AND data_compensacao BETWEEN $1 AND $2
       ORDER BY data_compensacao`,
      [hoje, em30]
    );

    const totalEntrada = chequesEntrada.rows.reduce((a, c) => a + parseFloat(c.valor), 0);
    const totalSaida = contas.rows.reduce((a, c) => a + parseFloat(c.valor), 0)
                     + chequesSaida.rows.reduce((a, c) => a + parseFloat(c.valor), 0);

    res.json({
      periodo: { de: hoje, ate: em30 },
      entradas: { cheques: chequesEntrada.rows, total: totalEntrada },
      saidas: { contas: contas.rows, cheques: chequesSaida.rows, total: totalSaida },
      saldoProjetado: totalEntrada - totalSaida
    });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// FINANCEIRO — DRE MENSAL
app.get('/api/financeiro/dre', auth, async (req, res) => {
  try {
    const { mes } = req.query; // formato YYYY-MM
    if (!mes) return res.status(400).json({ erro: 'Informe o mês' });

    // Receita bruta (vendas pagas no mês)
    const vendas = await pool.query(
      `SELECT COALESCE(SUM(tot),0) as receita, COUNT(*) as qtd_vendas
       FROM vendas WHERE TO_CHAR(data,'YYYY-MM')=$1 AND status='pago'`,
      [mes]
    );

    // CMV — custo dos produtos vendidos
    const cmv = await pool.query(
      `SELECT COALESCE(SUM(vi.qty * p.custo),0) as cmv
       FROM venda_itens vi
       JOIN vendas v ON v.id=vi.venda_id
       JOIN produtos p ON p.id=vi.produto_id
       WHERE TO_CHAR(v.data,'YYYY-MM')=$1 AND v.status='pago'`,
      [mes]
    );

    // Despesas por categoria
    const despesas = await pool.query(
      `SELECT categoria, COALESCE(SUM(valor_pago),SUM(valor)) as total
       FROM contas_pagar
       WHERE TO_CHAR(vencimento,'YYYY-MM')=$1 AND pago=TRUE
       GROUP BY categoria ORDER BY total DESC`,
      [mes]
    );

    // Total despesas
    const totalDespesas = despesas.rows.reduce((a, d) => a + parseFloat(d.total), 0);

    const receitaBruta = parseFloat(vendas.rows[0].receita);
    const cmvTotal = parseFloat(cmv.rows[0].cmv);
    const lucroBruto = receitaBruta - cmvTotal;
    const lucroLiquido = lucroBruto - totalDespesas;

    res.json({
      mes,
      receitaBruta,
      cmv: cmvTotal,
      lucroBruto,
      despesas: despesas.rows,
      totalDespesas,
      lucroLiquido,
      qtdVendas: parseInt(vendas.rows[0].qtd_vendas)
    });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// FINANCEIRO — CHEQUES
app.get('/api/financeiro/cheques', auth, async (req, res) => {
  try {
    const { tipo, status, mes } = req.query;
    let where = ['1=1'];
    let params = [];
    let i = 1;
    if (tipo) { where.push(`tipo=$${i++}`); params.push(tipo); }
    if (status) { where.push(`status=$${i++}`); params.push(status); }
    if (mes) { where.push(`TO_CHAR(data_compensacao,'YYYY-MM')=$${i++}`); params.push(mes); }
    const r = await pool.query(
      `SELECT * FROM cheques WHERE ${where.join(' AND ')} ORDER BY data_compensacao`,
      params
    );
    res.json(r.rows);
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.post('/api/financeiro/cheques', auth, async (req, res) => {
  try {
    const c = req.body;
    await pool.query(
      `INSERT INTO cheques (id,tipo,valor,data_cheque,data_compensacao,nome,banco,numero,status,cliente_id,observacao)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       ON CONFLICT (id) DO UPDATE SET tipo=$2,valor=$3,data_cheque=$4,data_compensacao=$5,nome=$6,banco=$7,numero=$8,status=$9,cliente_id=$10,observacao=$11`,
      [c.id, c.tipo, c.valor, c.dataCheque, c.dataCompensacao, c.nome, c.banco||null, c.numero||null, c.status||'pendente', c.clienteId||null, c.observacao||null]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.patch('/api/financeiro/cheques/:id/status', auth, async (req, res) => {
  try {
    const { status } = req.body;
    await pool.query(`UPDATE cheques SET status=$1 WHERE id=$2`, [status, req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.delete('/api/financeiro/cheques/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM cheques WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// FINANCEIRO — CAIXA
app.get('/api/financeiro/caixa/hoje', auth, async (req, res) => {
  try {
    const hoje = new Date().toISOString().split('T')[0];
    const caixa = await pool.query(`SELECT * FROM caixa WHERE data=$1`, [hoje]);
    if (!caixa.rows.length) return res.json(null);
    const movimentos = await pool.query(
      `SELECT * FROM caixa_movimentos WHERE caixa_id=$1 ORDER BY criado_em`,
      [caixa.rows[0].id]
    );
    res.json({ ...caixa.rows[0], movimentos: movimentos.rows });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.get('/api/financeiro/caixa/:data', auth, async (req, res) => {
  try {
    const caixa = await pool.query(`SELECT * FROM caixa WHERE data=$1`, [req.params.data]);
    if (!caixa.rows.length) return res.json(null);
    const movimentos = await pool.query(
      `SELECT * FROM caixa_movimentos WHERE caixa_id=$1 ORDER BY criado_em`,
      [caixa.rows[0].id]
    );
    res.json({ ...caixa.rows[0], movimentos: movimentos.rows });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.post('/api/financeiro/caixa/abrir', auth, async (req, res) => {
  try {
    const { id, data, valorAbertura } = req.body;
    await pool.query(
      `INSERT INTO caixa (id,data,valor_abertura,status) VALUES ($1,$2,$3,'aberto')
       ON CONFLICT (data) DO NOTHING`,
      [id, data, valorAbertura]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.post('/api/financeiro/caixa/fechar', auth, async (req, res) => {
  try {
    const { id, valorFechamento, valorSistema, diferenca, observacao } = req.body;
    await pool.query(
      `UPDATE caixa SET valor_fechamento=$1,valor_sistema=$2,diferenca=$3,observacao=$4,status='fechado' WHERE id=$5`,
      [valorFechamento, valorSistema, diferenca, observacao||null, id]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.post('/api/financeiro/caixa/movimento', auth, async (req, res) => {
  try {
    const m = req.body;
    await pool.query(
      `INSERT INTO caixa_movimentos (id,caixa_id,tipo,descricao,valor,categoria,referencia_id,referencia_tipo)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [m.id, m.caixaId, m.tipo, m.descricao, m.valor, m.categoria||null, m.referenciaId||null, m.referenciaTipo||null]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.delete('/api/financeiro/caixa/movimento/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM caixa_movimentos WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// FINANCEIRO — CONTAS A PAGAR
app.get('/api/financeiro/contas-pagar', auth, async (req, res) => {
  try {
    const { mes, status, categoria } = req.query;
    let where = ['1=1'];
    let params = [];
    let i = 1;
    if (mes) { where.push(`TO_CHAR(vencimento,'YYYY-MM')=$${i++}`); params.push(mes); }
    if (status === 'pendente') { where.push(`pago=FALSE`); }
    else if (status === 'pago') { where.push(`pago=TRUE`); }
    if (categoria) { where.push(`categoria=$${i++}`); params.push(categoria); }
    const r = await pool.query(
      `SELECT * FROM contas_pagar WHERE ${where.join(' AND ')} ORDER BY vencimento`,
      params
    );
    res.json(r.rows);
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.post('/api/financeiro/contas-pagar', auth, async (req, res) => {
  try {
    const c = req.body;
    await pool.query(
      `INSERT INTO contas_pagar (id,descricao,categoria,valor,vencimento,pago,data_pagamento,valor_pago,forma_pagamento,observacao,recorrente)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       ON CONFLICT (id) DO UPDATE SET descricao=$2,categoria=$3,valor=$4,vencimento=$5,pago=$6,data_pagamento=$7,valor_pago=$8,forma_pagamento=$9,observacao=$10,recorrente=$11`,
      [c.id,c.descricao,c.categoria,c.valor,c.vencimento,c.pago||false,c.dataPagamento||null,c.valorPago||null,c.formaPagamento||null,c.observacao||null,c.recorrente||false]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.patch('/api/financeiro/contas-pagar/:id/pagar', auth, async (req, res) => {
  try {
    const { dataPagamento, valorPago, formaPagamento } = req.body;
    await pool.query(
      `UPDATE contas_pagar SET pago=TRUE,data_pagamento=$1,valor_pago=$2,forma_pagamento=$3 WHERE id=$4`,
      [dataPagamento||new Date().toISOString().split('T')[0], valorPago||null, formaPagamento||null, req.params.id]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.delete('/api/financeiro/contas-pagar/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM contas_pagar WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

async function gerarBackup() {
  const [
    funcionarios, produtos, clientes, fornecedores,
    vendas, categorias, contasPagar, cheques, caixa,
    caixaMovimentos, metasComissao
  ] = await Promise.all([
    pool.query('SELECT * FROM funcionarios'),
    pool.query('SELECT * FROM produtos'),
    pool.query('SELECT * FROM clientes'),
    pool.query('SELECT * FROM fornecedores'),
    pool.query('SELECT * FROM vendas'),
    pool.query('SELECT * FROM categorias'),
    pool.query('SELECT * FROM contas_pagar'),
    pool.query('SELECT * FROM cheques'),
    pool.query('SELECT * FROM caixa'),
    pool.query('SELECT * FROM caixa_movimentos'),
    pool.query('SELECT * FROM metas_comissao')
  ]);
  return {
    geradoEm: new Date().toISOString(),
    versao: '1.0',
    funcionarios: funcionarios.rows,
    produtos: produtos.rows,
    clientes: clientes.rows,
    fornecedores: fornecedores.rows,
    vendas: vendas.rows,
    categorias: categorias.rows,
    contasPagar: contasPagar.rows,
    cheques: cheques.rows,
    caixa: caixa.rows,
    caixaMovimentos: caixaMovimentos.rows,
    metasComissao: metasComissao.rows
  };
}

// BACKUP — Exportação manual
app.get('/api/backup/exportar', auth, async (req, res) => {
  try {
    const backup = await gerarBackup();
    const json = JSON.stringify(backup, null, 2);
    const jsonCriptografado = criptografarBackup(json);
    const data = new Date().toISOString().split('T')[0];
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="scap-backup-${data}.enc"`);
    res.send(jsonCriptografado);
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// BACKUP — Descriptografar
app.post('/api/backup/descriptografar', auth, async (req, res) => {
  try {
    const { conteudo } = req.body;
    const BACKUP_SECRET = process.env.BACKUP_SECRET || 'scap-moda-backup-2024';
    const [ivHex, encrypted] = conteudo.split(':');
    const key = crypto.scryptSync(BACKUP_SECRET, 'salt', 32);
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    const backup = JSON.parse(decrypted);
    res.json({ ok: true, backup });
  } catch (err) {
    res.status(400).json({ ok: false, erro: 'Senha incorreta ou arquivo inválido' });
  }
});

// BACKUP — Envio manual por e-mail
app.post('/api/backup/enviar-email', auth, async (req, res) => {
  try {
    const { email } = req.body;
    const backup = await gerarBackup();
    const json = JSON.stringify(backup, null, 2);
    const jsonCriptografado = criptografarBackup(json);
    const data = new Date().toISOString().split('T')[0];
    const stats = {
      funcionarios: backup.funcionarios.length,
      produtos: backup.produtos.length,
      clientes: backup.clientes.length,
      vendas: backup.vendas.length
    };
    await resend.emails.send({
      from: 'onboarding@resend.dev',
      to: email,
      subject: `Backup Scap Moda — ${data}`,
      html: `
        <h2>Backup Scap Moda Feminina</h2>
        <p>Backup gerado em ${new Date().toLocaleString('pt-BR')}</p>
        <ul>
          <li>${stats.funcionarios} funcionários</li>
          <li>${stats.produtos} produtos</li>
          <li>${stats.clientes} clientes</li>
          <li>${stats.vendas} vendas</li>
        </ul>
        <p>O arquivo criptografado com todos os dados está em anexo.</p>
      `,
      attachments: [{
        filename: `scap-backup-${data}.enc`,
        content: Buffer.from(jsonCriptografado).toString('base64')
      }]
    });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// BACKUP — Automático diário às 23h
const agendarBackupDiario = () => {
  const agora = new Date();
  const proximas23h = new Date();
  proximas23h.setHours(23, 0, 0, 0);
  if (agora >= proximas23h) {
    proximas23h.setDate(proximas23h.getDate() + 1);
  }
  const msAte23h = proximas23h - agora;
  setTimeout(async () => {
    try {
      const cfg = await pool.query(`SELECT valor FROM configuracoes WHERE chave='backup_email'`);
      const email = cfg.rows[0]?.valor || 'dmeschick@hotmail.com';
      const backup = await gerarBackup();
      const json = JSON.stringify(backup, null, 2);
      const jsonCriptografado = criptografarBackup(json);
      const data = new Date().toISOString().split('T')[0];
      await resend.emails.send({
        from: 'onboarding@resend.dev',
        to: email,
        subject: `Backup automático Scap Moda — ${data}`,
        html: `
          <h2>Backup automático Scap Moda Feminina</h2>
          <p>Backup automático gerado em ${new Date().toLocaleString('pt-BR')}</p>
          <ul>
            <li>${backup.funcionarios.length} funcionários</li>
            <li>${backup.produtos.length} produtos</li>
            <li>${backup.clientes.length} clientes</li>
            <li>${backup.vendas.length} vendas</li>
          </ul>
          <p>O arquivo criptografado com todos os dados está em anexo.</p>
        `,
        attachments: [{
          filename: `scap-backup-${data}.enc`,
          content: Buffer.from(jsonCriptografado).toString('base64')
        }]
      });
      console.log('Backup diário enviado para', email);
    } catch (err) {
      console.error('Erro no backup diário:', err.message);
    }
    agendarBackupDiario();
  }, msAte23h);
};



// RELATÓRIO DIÁRIO
app.get('/api/relatorios/diario', auth, async (req, res) => {
  try {
    const { data } = req.query;
    if (!data) return res.status(400).json({ erro: 'Informe a data' });

    // Vendas do dia (exceto canceladas)
    const vendas = await pool.query(
      `SELECT v.*,
        f.nome as vendedor_nome_join
       FROM vendas v
       LEFT JOIN funcionarios f ON f.id = v.vendedor_id
       WHERE DATE(v.data AT TIME ZONE 'America/Sao_Paulo') = $1
         AND v.status != 'cancelada'`,
      [data]
    );

    // Itens vendidos do dia
    const itens = await pool.query(
      `SELECT vi.*, p.custo, p.nome as produto_nome
       FROM venda_itens vi
       JOIN vendas v ON v.id = vi.venda_id
       LEFT JOIN produtos p ON p.id = vi.produto_id
       WHERE DATE(v.data AT TIME ZONE 'America/Sao_Paulo') = $1
         AND v.status != 'cancelada'`,
      [data]
    );

    // Pagamentos do dia
    const pagamentos = await pool.query(
      `SELECT vp.*
       FROM venda_pagamentos vp
       JOIN vendas v ON v.id = vp.venda_id
       WHERE DATE(v.data AT TIME ZONE 'America/Sao_Paulo') = $1
         AND v.status != 'cancelada'`,
      [data]
    );

    // --- Cálculos ---

    // Total geral da loja
    const totalLoja = vendas.rows.reduce((a, v) => a + parseFloat(v.tot || 0) + parseFloat(v.credito_gerado || 0), 0);

    // Por vendedor
    const porVendedor = {};
    vendas.rows.forEach(v => {
      const nome = v.vendedor_nome_join || v.vendedor_nome || 'Sem vendedor';
      if (!porVendedor[nome]) porVendedor[nome] = { nome, total: 0, pecas: 0 };
      porVendedor[nome].total += parseFloat(v.tot || 0) + parseFloat(v.credito_gerado || 0);
    });

    // Peças por vendedor (itens novos)
    itens.rows.filter(i => i.tipo !== 'devolvido').forEach(i => {
      // Busca o vendedor da venda
      const venda = vendas.rows.find(v => v.id === i.venda_id);
      const nome = venda?.vendedor_nome_join || venda?.vendedor_nome || 'Sem vendedor';
      if (porVendedor[nome]) porVendedor[nome].pecas += parseInt(i.qty || 0);
    });

    // Por forma de pagamento (agrupado por tipo e parcelas)
    const porPagamento = {};
    pagamentos.rows.forEach(p => {
      let chave = p.tipo;
      if (p.tipo === 'credito') {
        chave = p.parcelas > 1 ? 'credito_' + p.parcelas + 'x' : 'credito_1x';
      }
      if (!porPagamento[chave]) porPagamento[chave] = { tipo: p.tipo, parcelas: p.parcelas || 1, total: 0, label: '' };
      porPagamento[chave].total += parseFloat(p.valor || 0);
    });

    // Labels de pagamento
    const labels = { dinheiro: 'Dinheiro', pix: 'PIX', debito: 'Débito', cheque: 'Cheque à vista', cheque_pre: 'Cheque pré-datado', credito_1x: 'Crédito à vista' };
    Object.keys(porPagamento).forEach(k => {
      if (k.startsWith('credito_') && k !== 'credito_1x') {
        const parc = k.replace('credito_', '').replace('x', '');
        porPagamento[k].label = 'Crédito ' + parc + 'x';
      } else {
        porPagamento[k].label = labels[k] || k;
      }
    });

    // Total de peças vendidas (itens novos)
    const totalPecasVendidas = itens.rows
      .filter(i => i.tipo !== 'devolvido')
      .reduce((a, i) => a + parseInt(i.qty || 0), 0);

    // Total de peças trocadas (itens devolvidos)
    const totalPecasTrocadas = itens.rows
      .filter(i => i.tipo === 'devolvido')
      .reduce((a, i) => a + parseInt(i.qty || 0), 0);

    // CMV — custo das mercadorias vendidas
    const cmv = itens.rows
      .filter(i => i.tipo !== 'devolvido')
      .reduce((a, i) => a + (parseFloat(i.custo || 0) * parseInt(i.qty || 0)), 0);

    // Margem bruta
    const margemBruta = totalLoja > 0 ? ((totalLoja - cmv) / totalLoja * 100) : 0;

    res.json({
      data,
      totalLoja: Math.round(totalLoja * 100) / 100,
      porVendedor: Object.values(porVendedor).sort((a, b) => b.total - a.total),
      porPagamento: Object.values(porPagamento).sort((a, b) => b.total - a.total),
      totalPecasVendidas,
      totalPecasTrocadas,
      cmv: Math.round(cmv * 100) / 100,
      margemBruta: Math.round(margemBruta * 100) / 100,
      qtdVendas: vendas.rows.length
    });

  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// VENDAS — Gerar próximo número
app.post('/api/vendas/proximo-numero', auth, async (req, res) => {
  try {
    const r = await pool.query(`SELECT NEXTVAL('venda_num_seq') as num`);
    const num = '#' + String(r.rows[0].num).padStart(4, '0');
    res.json({ num });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

initDB().then(() => {
  app.listen(PORT, () => console.log(`Scap Moda rodando na porta ${PORT}`));
  agendarBackupDiario();
});
