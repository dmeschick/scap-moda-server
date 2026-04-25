// deploy: 2026-04-06
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
app.set('trust proxy', 1);
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
const limiterConfirmacaoSenha = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 80,
  message: { erro: 'Muitas confirmações de senha. Aguarde alguns minutos e tente novamente.' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true
});
app.use('/api/login', limiterLogin);
app.use('/api/auth/validar-senha', limiterConfirmacaoSenha);
app.use('/api/auth/validar-admin', limiterConfirmacaoSenha);
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
const isBcryptHash = hash => /^\$2[aby]\$/.test(String(hash || ''));
const dataLocalISO = (data = new Date()) => {
  const partes = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'America/Sao_Paulo',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  }).formatToParts(data).reduce((acc, p) => {
    acc[p.type] = p.value;
    return acc;
  }, {});
  return `${partes.year}-${partes.month}-${partes.day}`;
};
const OPENAI_VISION_MODEL = process.env.OPENAI_VISION_MODEL || 'gpt-4.1';
const QZ_CERTIFICATE = carregarTextoEnv('QZ_CERTIFICATE', 'QZ_CERTIFICATE_B64');
const QZ_PRIVATE_KEY = carregarTextoEnv('QZ_PRIVATE_KEY', 'QZ_PRIVATE_KEY_B64');
const QZ_PRIVATE_KEY_PASSPHRASE = process.env.QZ_PRIVATE_KEY_PASSPHRASE || '';
const IMPORT_PRODUTO_CONFIG = {
  'blusas': { categoria: 'Blusas', sufixo: 'B', ncm: '61062000', aliases: ['blusa', 'blusas'] },
  'vestidos': { categoria: 'Vestidos', sufixo: 'V', ncm: '61044300', aliases: ['vestido', 'vestidos'] },
  'calcas': { categoria: 'Calças', sufixo: 'C', ncm: '61034300', aliases: ['calca', 'calcas', 'calça', 'calças'] },
  'shorts': { categoria: 'Shorts', sufixo: 'H', ncm: '61123100', aliases: ['short', 'shorts'] },
  'saias': { categoria: 'Saias', sufixo: 'S', ncm: '61045300', aliases: ['saia', 'saias'] },
  'conjuntos': { categoria: 'Conjuntos', sufixo: 'U', ncm: '61042300', aliases: ['conjunto', 'conjuntos'] },
  'macacoes': { categoria: 'Macacões', sufixo: 'M', ncm: '61122000', aliases: ['macacao', 'macacoes', 'macacão', 'macacões'] },
  'acessorios': { categoria: 'Acessórios', sufixo: 'A', ncm: '62171000', aliases: ['acessorio', 'acessorios', 'acessório', 'acessórios', 'bolsa', 'bolsas'] }
};

function carregarTextoEnv(nomeTexto, nomeBase64) {
  const texto = process.env[nomeTexto];
  if (texto) return texto.replace(/\\n/g, '\n').trim();
  const base64 = process.env[nomeBase64];
  if (!base64) return '';
  try {
    return Buffer.from(base64, 'base64').toString('utf8').replace(/\\n/g, '\n').trim();
  } catch (err) {
    console.warn(`Não foi possível ler ${nomeBase64}:`, err.message);
    return '';
  }
}

function qzTrayConfigurado() {
  return !!(QZ_CERTIFICATE && QZ_PRIVATE_KEY);
}

function normalizarTextoBase(s) {
  return String(s || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().trim();
}

function normalizarNCM(valor) {
  const digitos = String(valor || '').replace(/\D/g, '');
  return digitos.length === 8 ? digitos : '';
}

function hashToken(token) {
  return crypto.createHash('sha256').update(String(token || '')).digest('hex');
}

function detectarCategoriaImportacao(texto) {
  const base = normalizarTextoBase(texto);
  const cfg = Object.values(IMPORT_PRODUTO_CONFIG).find(item =>
    item.aliases.some(alias => {
      const alvo = normalizarTextoBase(alias);
      return base.includes('\n' + alvo + '\n') || base.startsWith(alvo + '\n') || base.includes(alvo);
    })
  );
  return cfg ? cfg.categoria : '';
}

function calcularMesDesconto(tipo, dataRef) {
  const d = dataRef ? new Date(dataRef) : new Date();
  const dia = d.getDate();
  let ano = d.getFullYear();
  let mes = d.getMonth(); // 0-based
  if (tipo === 'dinheiro') {
    mes += 1;
  } else {
    mes += dia < 20 ? 1 : 2;
  }
  if (mes > 11) { ano += Math.floor(mes / 12); mes = mes % 12; }
  return `${ano}-${String(mes + 1).padStart(2, '0')}`;
}
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

async function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '') || req.query.token;
  if (!token) return res.status(401).json({ erro: 'Não autorizado' });
  const tokenHash = hashToken(token);
  if (tokenBlacklist.has(tokenHash)) return res.status(401).json({ erro: 'Sessão encerrada. Faça login novamente.' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    req.token = token;
    req.tokenHash = tokenHash;
    const r = await pool.query(
      `SELECT 1
       FROM token_blacklist
       WHERE token_hash = $1
         AND expires_at > NOW()
       LIMIT 1`,
      [tokenHash]
    );
    if (r.rows.length) {
      tokenBlacklist.add(tokenHash);
      return res.status(401).json({ erro: 'Sessão encerrada. Faça login novamente.' });
    }
    next();
  }
  catch (err) {
    if (err.name === 'TokenExpiredError') return res.status(401).json({ erro: 'Sessão expirada. Faça login novamente.' });
    res.status(401).json({ erro: 'Token inválido' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.cargo !== 'Administrador') {
    return res.status(403).json({ erro: 'Acesso restrito a administradores.' });
  }
  next();
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
      data_entrada DATE,
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
    CREATE TABLE IF NOT EXISTS orcamentos (
      id VARCHAR(50) PRIMARY KEY,
      num VARCHAR(20),
      data TIMESTAMP DEFAULT NOW(),
      validade DATE,
      cliente_id VARCHAR(50),
      cliente_nome VARCHAR(200),
      cliente_tel VARCHAR(30),
      vendedor_id VARCHAR(50),
      vendedor_nome VARCHAR(200),
      canal VARCHAR(20) DEFAULT 'presencial',
      subtotal DECIMAL(10,2) DEFAULT 0,
      desconto DECIMAL(10,2) DEFAULT 0,
      desc_pct DECIMAL(5,2) DEFAULT 0,
      total DECIMAL(10,2) DEFAULT 0,
      obs TEXT,
      status VARCHAR(20) DEFAULT 'aberto',
      convertido_venda_id VARCHAR(50),
      convertido_em TIMESTAMP,
      criado_em TIMESTAMP DEFAULT NOW(),
      atualizado_em TIMESTAMP DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_orcamentos_status ON orcamentos(status);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_orcamentos_num ON orcamentos(num);
    CREATE TABLE IF NOT EXISTS orcamento_itens (
      id SERIAL PRIMARY KEY,
      orcamento_id VARCHAR(50) REFERENCES orcamentos(id) ON DELETE CASCADE,
      produto_id VARCHAR(50),
      nome VARCHAR(200),
      cod VARCHAR(50),
      preco DECIMAL(10,2),
      qty INTEGER,
      tipo VARCHAR(20) DEFAULT 'novo'
    );
    ALTER TABLE orcamento_itens ADD COLUMN IF NOT EXISTS tipo VARCHAR(20) DEFAULT 'novo';
    CREATE TABLE IF NOT EXISTS atendimentos_pdv (
      id VARCHAR(50) PRIMARY KEY,
      nome VARCHAR(100),
      usuario_id VARCHAR(50),
      usuario_nome VARCHAR(200),
      cliente_id VARCHAR(50),
      cliente_nome VARCHAR(200),
      vendedor_id VARCHAR(50),
      vendedor_nome VARCHAR(200),
      total NUMERIC(10,2) DEFAULT 0,
      qtd_pecas INTEGER DEFAULT 0,
      estado JSONB NOT NULL DEFAULT '{}',
      status VARCHAR(20) DEFAULT 'aberto',
      criado_em TIMESTAMP DEFAULT NOW(),
      atualizado_em TIMESTAMP DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_atendimentos_pdv_status ON atendimentos_pdv(status, atualizado_em DESC);
    CREATE INDEX IF NOT EXISTS idx_atendimentos_pdv_status_criado ON atendimentos_pdv(status, criado_em ASC, id ASC);
    CREATE TABLE IF NOT EXISTS configuracoes (
      chave VARCHAR(100) PRIMARY KEY,
      valor JSONB,
      atualizado_em TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS importacao_foto_correcoes (
      id VARCHAR(50) PRIMARY KEY,
      categoria VARCHAR(100),
      colecao VARCHAR(100),
      original JSONB NOT NULL DEFAULT '{}',
      corrigido JSONB NOT NULL DEFAULT '{}',
      criado_em TIMESTAMP DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_importacao_foto_correcoes_cat ON importacao_foto_correcoes(categoria, criado_em DESC);
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
    CREATE TABLE IF NOT EXISTS vales_funcionarios (
      id TEXT PRIMARY KEY,
      funcionario_id TEXT NOT NULL,
      funcionario_nome TEXT,
      valor NUMERIC(10,2) NOT NULL,
      tipo TEXT NOT NULL DEFAULT 'dinheiro',
      descricao TEXT,
      mes TEXT NOT NULL,
      venda_id TEXT,
      status TEXT DEFAULT 'pendente',
      criado_em TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS vale_itens (
      id TEXT PRIMARY KEY,
      vale_id TEXT NOT NULL,
      produto_id TEXT NOT NULL,
      produto_nome TEXT,
      produto_cod TEXT,
      qty INTEGER NOT NULL DEFAULT 1,
      preco_cheio NUMERIC(10,2) NOT NULL,
      preco_desc NUMERIC(10,2) NOT NULL
    );
    ALTER TABLE vales_funcionarios ADD COLUMN IF NOT EXISTS parcelas INTEGER DEFAULT 1;
    ALTER TABLE vales_funcionarios ADD COLUMN IF NOT EXISTS vl_parcela NUMERIC(10,2);
    ALTER TABLE vales_funcionarios ADD COLUMN IF NOT EXISTS mes_desconto TEXT;
    ALTER TABLE vales_funcionarios ADD COLUMN IF NOT EXISTS parcelas_pagas INTEGER DEFAULT 0;
  `);

  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM configuracoes WHERE chave = 'migration_acessorios_20260226'
      ) THEN
        UPDATE produtos
        SET data_entrada = '2026-02-26'
        WHERE cat IN ('Acessórios', 'Acessorios')
          AND data_entrada IS NULL;

        UPDATE produtos
        SET colecao = 'Outono-Inverno 2026',
            atualizado_em = NOW()
        WHERE cat IN ('Acessórios', 'Acessorios');

        INSERT INTO configuracoes (chave, valor, atualizado_em)
        VALUES (
          'migration_acessorios_20260226',
          '{"descricao":"Define data e colecao dos acessorios existentes em 2026-04-21"}'::jsonb,
          NOW()
        );
      END IF;
    END $$;
  `);

  // Popula mes_desconto nos vales antigos que não têm o campo preenchido
  await pool.query(`
    UPDATE vales_funcionarios
    SET mes_desconto = (
      CASE
        WHEN tipo = 'dinheiro' THEN
          TO_CHAR(DATE_TRUNC('month', criado_em) + INTERVAL '1 month', 'YYYY-MM')
        WHEN tipo = 'roupa' AND EXTRACT(DAY FROM criado_em) < 20 THEN
          TO_CHAR(DATE_TRUNC('month', criado_em) + INTERVAL '1 month', 'YYYY-MM')
        WHEN tipo = 'roupa' AND EXTRACT(DAY FROM criado_em) >= 20 THEN
          TO_CHAR(DATE_TRUNC('month', criado_em) + INTERVAL '2 months', 'YYYY-MM')
        ELSE
          TO_CHAR(DATE_TRUNC('month', criado_em) + INTERVAL '1 month', 'YYYY-MM')
      END
    )
    WHERE mes_desconto IS NULL
  `);
  // Remove vendas duplicadas por número (mantém a mais antiga) antes de criar índice único
  await pool.query(`
    DELETE FROM vendas
    WHERE COALESCE(num, '') <> ''
      AND id NOT IN (
        SELECT DISTINCT ON (num) id
        FROM vendas
        WHERE COALESCE(num, '') <> ''
        ORDER BY num, data ASC
      )
  `);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS idx_vendas_num ON vendas(num)`);
  // Adiciona colunas que podem não existir em bancos criados antes dessas definições
  await pool.query(`ALTER TABLE clientes ADD COLUMN IF NOT EXISTS criado_em TIMESTAMP DEFAULT NOW()`);
  await pool.query(`ALTER TABLE enderecos_cliente ADD COLUMN IF NOT EXISTS uf TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE enderecos_cliente ADD COLUMN IF NOT EXISTS cMun TEXT DEFAULT '9999999'`);
  await pool.query(`
    UPDATE enderecos_cliente
    SET uf = estado
    WHERE COALESCE(uf, '') = ''
      AND COALESCE(estado, '') <> ''
  `);
  // Corrigir cMun via CEP (sem problema de encoding/acento) — faixa Petrópolis 25600000–25799999
  await pool.query(`
    UPDATE enderecos_cliente
    SET cMun = '3304557'
    WHERE cMun = '9999999'
    AND estado = 'RJ'
    AND REPLACE(cep, '-', '') >= '25600000'
    AND REPLACE(cep, '-', '') <= '25799999'
  `);
  await pool.query(`ALTER TABLE vendas ADD COLUMN IF NOT EXISTS credito_gerado NUMERIC(10,2) DEFAULT 0`);
  await pool.query(`ALTER TABLE vendas ADD COLUMN IF NOT EXISTS desc_pct NUMERIC(5,2) DEFAULT 0`);
  await pool.query(`ALTER TABLE vendas ADD COLUMN IF NOT EXISTS desconto_manual NUMERIC(10,2) DEFAULT 0`);
  await pool.query(`ALTER TABLE vendas ADD COLUMN IF NOT EXISTS nfe_id TEXT`);
  await pool.query(`ALTER TABLE vendas ADD COLUMN IF NOT EXISTS nfe_numero TEXT`);
  await pool.query(`ALTER TABLE vendas ADD COLUMN IF NOT EXISTS nfe_situacao TEXT`);
  await pool.query(`ALTER TABLE vendas ADD COLUMN IF NOT EXISTS nfce_id TEXT`);
  await pool.query(`ALTER TABLE vendas ADD COLUMN IF NOT EXISTS nfce_numero TEXT`);
  await pool.query(`ALTER TABLE vendas ADD COLUMN IF NOT EXISTS nfce_situacao TEXT`);
  await pool.query(`ALTER TABLE caixa ADD COLUMN IF NOT EXISTS detalhes JSONB DEFAULT '{}'`);
  await pool.query(`ALTER TABLE caixa ADD COLUMN IF NOT EXISTS fechado_por TEXT`);
  await pool.query(`ALTER TABLE caixa ADD COLUMN IF NOT EXISTS fechado_em TIMESTAMP`);
  await pool.query(`ALTER TABLE categorias ADD COLUMN IF NOT EXISTS sufixo TEXT DEFAULT ''`);
  await pool.query(`ALTER TABLE produtos ADD COLUMN IF NOT EXISTS criado_em TIMESTAMP DEFAULT NOW()`);
  await pool.query(`ALTER TABLE produtos ADD COLUMN IF NOT EXISTS data_entrada DATE`);
  for (const cfg of Object.values(IMPORT_PRODUTO_CONFIG)) {
    await pool.query(
      `INSERT INTO categorias (id, nome, sufixo)
       VALUES ($1, $2, $3)
       ON CONFLICT (nome) DO UPDATE SET sufixo = EXCLUDED.sufixo`,
      [normalizarTextoBase(cfg.categoria), cfg.categoria, cfg.sufixo]
    );
  }
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
  await pool.query(`CREATE TABLE IF NOT EXISTS bling_tokens (
    id INTEGER PRIMARY KEY DEFAULT 1,
    access_token TEXT,
    refresh_token TEXT,
    expires_at TIMESTAMP,
    atualizado_em TIMESTAMP DEFAULT NOW()
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS token_blacklist (
    token_hash TEXT PRIMARY KEY,
    expires_at TIMESTAMP NOT NULL,
    criado_em TIMESTAMP DEFAULT NOW()
  )`);
  await pool.query(`DELETE FROM token_blacklist WHERE expires_at <= NOW()`);
  await pool.query(`
    SELECT SETVAL('venda_num_seq',
      COALESCE(
        (SELECT MAX(CAST(REPLACE(num, '#', '') AS INTEGER)) FROM vendas WHERE num ~ '^#[0-9]+$'),
        1
      ),
      EXISTS(SELECT 1 FROM vendas WHERE num ~ '^#[0-9]+$')
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
    if (isBcryptHash(func.senha_hash)) {
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
  (async () => {
    if (req.tokenHash) {
      tokenBlacklist.add(req.tokenHash);
      const expDate = req.user?.exp ? new Date(req.user.exp * 1000) : new Date(Date.now() + 10 * 60 * 60 * 1000);
      await pool.query(
        `INSERT INTO token_blacklist (token_hash, expires_at)
         VALUES ($1, $2)
         ON CONFLICT (token_hash) DO UPDATE SET expires_at = EXCLUDED.expires_at`,
        [req.tokenHash, expDate]
      );
    }
    res.json({ ok: true });
  })().catch(err => res.status(500).json({ erro: err.message }));
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
    if (isBcryptHash(func.senha_hash)) {
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

// AUTH - Validar senha de um administrador para ações críticas
app.post('/api/auth/validar-admin', auth, async (req, res) => {
  try {
    const { senha } = req.body;
    if (!senha) return res.json({ ok: false, erro: 'Informe a senha do administrador.' });

    const r = await pool.query(
      `SELECT * FROM funcionarios
       WHERE status='ativo'
         AND cargo IN ('Administrador', 'Proprietária')
       ORDER BY cargo, nome`
    );

    for (const func of r.rows) {
      let senhaCorreta = false;
      if (isBcryptHash(func.senha_hash)) {
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
      if (senhaCorreta) {
        return res.json({ ok: true, admin: { id: func.id, nome: func.nome, cargo: func.cargo } });
      }
    }

    res.json({ ok: false, erro: 'Senha de administrador incorreta.' });
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
      sql = `SELECT id,nome,cpf,cargo,tel,salario,comissao,admissao,turno,obs,status,foto
             FROM funcionarios
             WHERE status='ativo'
               AND cargo IN ('Administrador', 'Gerente', 'Proprietária', 'Proprietaria')
             ORDER BY nome`;
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
    const { q, cat, status, limit, offset, dataEntradaIni, dataEntradaFim } = req.query;
    let where = [];
    let params = [];
    let i = 1;
    where.push(`status=${status ? `$${i++}` : "'ativo'"}`);
    if (status) params.push(status);
    if (cat) { where.push(`cat=$${i++}`); params.push(cat); }
    if (q) { where.push(`(LOWER(nome) LIKE $${i} OR cod ILIKE $${i})`); params.push('%'+q.toLowerCase()+'%'); i++; }
    if (dataEntradaIni) { where.push(`data_entrada >= $${i++}`); params.push(dataEntradaIni); }
    if (dataEntradaFim) { where.push(`data_entrada <= $${i++}`); params.push(dataEntradaFim); }
    const orderBy = cat
      ? "ORDER BY NULLIF(regexp_replace(cod, '\\D', '', 'g'), '')::bigint DESC NULLS LAST, cod DESC"
      : 'ORDER BY criado_em DESC';
    const sql = `SELECT * FROM produtos WHERE ${where.join(' AND ')} ${orderBy} LIMIT ${parseInt(limit)||500} OFFSET ${parseInt(offset)||0}`;
    const r = await pool.query(sql, params);
    res.json(r.rows);
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.get('/api/produtos/codigos-existentes', auth, async (req, res) => {
  try {
    const codigos = String(req.query.codigos || '')
      .split(',')
      .map(c => c.trim())
      .filter(Boolean);
    if (!codigos.length) return res.json([]);
    const unicos = [...new Set(codigos)].slice(0, 500);
    const r = await pool.query(
      "SELECT cod FROM produtos WHERE status = 'ativo' AND cod = ANY($1::text[])",
      [unicos]
    );
    res.json(r.rows.map(row => row.cod));
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.get('/api/relatorios/entradas-produtos', auth, async (req, res) => {
  try {
    const { inicio, fim } = req.query;
    if (!inicio || !fim) return res.status(400).json({ erro: 'Período inválido' });
    const resumo = await pool.query(
      `SELECT
         COUNT(*)::int AS qtd_produtos,
         COALESCE(SUM(est), 0)::int AS qtd_pecas,
         COALESCE(SUM(custo * est), 0) AS valor_custo,
         COALESCE(SUM(venda * est), 0) AS valor_venda
       FROM produtos
       WHERE status = 'ativo'
         AND data_entrada BETWEEN $1 AND $2`,
      [inicio, fim]
    );
    const itens = await pool.query(
      `SELECT id, cod, nome, cat, colecao, data_entrada, est, custo, venda
       FROM produtos
       WHERE status = 'ativo'
         AND data_entrada BETWEEN $1 AND $2
       ORDER BY data_entrada DESC, criado_em DESC
       LIMIT 200`,
      [inicio, fim]
    );
    res.json({
      resumo: resumo.rows[0] || { qtd_produtos: 0, qtd_pecas: 0, valor_custo: 0, valor_venda: 0 },
      itens: itens.rows
    });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

function limparLinhaCorrecaoImportacao(linha = {}) {
  return {
    ref_papel: String(linha.ref_papel ?? linha.refInt ?? '').trim(),
    ref_ext: String(linha.ref_ext ?? linha.refExt ?? '').trim(),
    descricao: String(linha.descricao ?? linha.nome ?? '').trim(),
    fornecedor: String(linha.fornecedor ?? '').trim(),
    data: String(linha.data ?? '').trim(),
    pc: Number(linha.pc ?? linha.custo ?? 0) || 0,
    pv: Number(linha.pv ?? linha.venda ?? 0) || 0,
    qtd: Number(linha.qtd ?? 0) || 0,
    categoria: String(linha.categoria ?? '').trim()
  };
}

function linhaCorrecaoTemValor(linha = {}) {
  return Boolean(
    linha.ref_papel ||
    linha.ref_ext ||
    linha.descricao ||
    linha.fornecedor ||
    linha.data ||
    linha.pc ||
    linha.pv ||
    linha.qtd
  );
}

function linhaCorrecaoMudou(original, corrigido) {
  return JSON.stringify(original) !== JSON.stringify(corrigido);
}

async function buscarCorrecoesImportacaoFoto(categoria, limite = 12) {
  const params = [];
  const where = [];
  if (categoria) {
    params.push(categoria);
    where.push(`(categoria = $${params.length} OR COALESCE(categoria, '') = '')`);
  }
  params.push(Math.max(1, Math.min(parseInt(limite) || 12, 30)));
  const sql = `
    SELECT original, corrigido
    FROM importacao_foto_correcoes
    ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
    ORDER BY criado_em DESC
    LIMIT $${params.length}
  `;
  const r = await pool.query(sql, params);
  return r.rows.map(row => ({
    original: limparLinhaCorrecaoImportacao(row.original || {}),
    corrigido: limparLinhaCorrecaoImportacao(row.corrigido || {})
  }));
}

function formatarCorrecoesParaPrompt(correcoes = []) {
  if (!correcoes.length) return '';
  return correcoes.map((ex, idx) => {
    return [
      `Exemplo ${idx + 1}:`,
      `IA leu: ${JSON.stringify(ex.original)}`,
      `Correção confirmada: ${JSON.stringify(ex.corrigido)}`
    ].join(' ');
  }).join('\n');
}

function schemaImportacaoProdutosIA() {
  return {
    type: 'object',
    additionalProperties: false,
    properties: {
      categoria: { type: 'string' },
      colecao: { type: 'string' },
      fornecedor_geral: { type: 'string' },
      observacoes_ia: { type: 'string' },
      itens: {
        type: 'array',
        items: {
          type: 'object',
          additionalProperties: false,
          properties: {
            ref_papel: { type: 'string' },
            ref_ext: { type: 'string' },
            descricao: { type: 'string' },
            fornecedor: { type: 'string' },
            data: { type: 'string' },
            pc: { type: 'number' },
            pv: { type: 'number' },
            qtd: { type: 'integer' },
            confianca: {
              type: 'object',
              additionalProperties: false,
              properties: {
                ref_papel: { type: 'string', enum: ['alta', 'media', 'baixa'] },
                ref_ext: { type: 'string', enum: ['alta', 'media', 'baixa'] },
                descricao: { type: 'string', enum: ['alta', 'media', 'baixa'] },
                fornecedor: { type: 'string', enum: ['alta', 'media', 'baixa'] },
                data: { type: 'string', enum: ['alta', 'media', 'baixa'] },
                pc: { type: 'string', enum: ['alta', 'media', 'baixa'] },
                pv: { type: 'string', enum: ['alta', 'media', 'baixa'] },
                qtd: { type: 'string', enum: ['alta', 'media', 'baixa'] }
              },
              required: ['ref_papel', 'ref_ext', 'descricao', 'fornecedor', 'data', 'pc', 'pv', 'qtd']
            },
            observacoes: { type: 'string' }
          },
          required: ['ref_papel', 'ref_ext', 'descricao', 'fornecedor', 'data', 'pc', 'pv', 'qtd', 'confianca', 'observacoes']
        }
      }
    },
    required: ['categoria', 'colecao', 'fornecedor_geral', 'observacoes_ia', 'itens']
  };
}

function extrairJsonRespostaOpenAI(data) {
  if (typeof data.output_text === 'string' && data.output_text.trim()) {
    return JSON.parse(data.output_text);
  }
  const txt = data.output?.flatMap(item => item.content || []).find(c => c.type === 'output_text')?.text;
  return txt ? JSON.parse(txt) : null;
}

app.post('/api/produtos/importar-foto/correcoes', auth, async (req, res) => {
  try {
    const { categoria, colecao, linhas } = req.body || {};
    if (!Array.isArray(linhas) || !linhas.length) {
      return res.status(400).json({ erro: 'Nenhuma correção enviada' });
    }
    let salvas = 0;
    for (const item of linhas.slice(0, 100)) {
      const original = limparLinhaCorrecaoImportacao(item.original || {});
      const corrigido = limparLinhaCorrecaoImportacao(item.corrigido || {});
      if (!linhaCorrecaoTemValor(corrigido) || !linhaCorrecaoMudou(original, corrigido)) continue;
      await pool.query(
        `INSERT INTO importacao_foto_correcoes (id, categoria, colecao, original, corrigido)
         VALUES ($1, $2, $3, $4, $5)`,
        [uid(), categoria || corrigido.categoria || '', colecao || '', original, corrigido]
      );
      salvas++;
    }
    res.json({ ok: true, salvas });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.post('/api/produtos/importar-foto/analisar', auth, async (req, res) => {
  try {
    if (!process.env.OPENAI_API_KEY) {
      return res.status(400).json({ erro: 'OPENAI_API_KEY não configurada no servidor' });
    }
    const { imageBase64, mimeType, categoria, colecao } = req.body || {};
    if (!imageBase64) return res.status(400).json({ erro: 'Imagem não enviada' });

    const categoriasTexto = Object.values(IMPORT_PRODUTO_CONFIG)
      .map(cfg => `${cfg.categoria} => sufixo ${cfg.sufixo}, NCM ${cfg.ncm}`)
      .join('; ');
    const exemplosCorrecoes = await buscarCorrecoesImportacaoFoto(categoria, 12);
    const exemplosCorrecoesTexto = formatarCorrecoesParaPrompt(exemplosCorrecoes);

    const systemPrompt = [
      'Você extrai dados de fichas manuscritas de cadastro de produtos de moda feminina.',
      'Leia a tabela da imagem e devolva APENAS JSON válido no schema solicitado.',
      'Regras importantes:',
      '- O título da folha indica a categoria principal da página.',
      '- A referência interna do papel é numérica e incompleta; preserve apenas o número lido no campo ref_papel.',
      '- Não invente linhas inexistentes.',
      '- Se um campo estiver ilegível, use string vazia para texto e 0 para números.',
      '- Os campos pc, pv e qtd devem ser números.',
      '- Preço de venda normalmente termina com centavos 90. Se ler apenas 159, considere 159.90. Se tiver dúvida, marque confiança baixa no campo pv.',
      '- Preço de custo pode ter centavos variados e deve ser lido exatamente como aparece.',
      '- Quantidade é sempre número inteiro.',
      '- Não confunda data, referência externa, preço e quantidade.',
      '- Se houver coleção escrita na folha, extraia. Caso contrário, use a coleção enviada pelo usuário se existir.',
      '- Se cada linha tiver seu próprio fornecedor, extraia no item. Se houver um fornecedor geral, repita nos itens quando fizer sentido.',
      '- Extraia a data de cada linha no formato DD-MM ou DD/MM/AAAA quando legível.',
      '- Para cada item, preencha confianca com alta, media ou baixa para ref_papel, ref_ext, descricao, fornecedor, data, pc, pv e qtd.',
      '- Em campos ilegíveis ou estimados, use confiança baixa e explique em observacoes.',
      '- Categorias válidas: ' + categoriasTexto,
      exemplosCorrecoesTexto
        ? 'Exemplos reais de correções anteriores desta loja. Use como referência para interpretar a caligrafia, abreviações e padrões de preço:\n' + exemplosCorrecoesTexto
        : ''
    ].join('\n');

    const userPrompt = [
      'Analise esta foto de uma folha de cadastro de produtos.',
      categoria ? `Categoria informada pelo usuário: ${categoria}` : 'Categoria informada pelo usuário: não informada',
      colecao ? `Coleção informada pelo usuário: ${colecao}` : 'Coleção informada pelo usuário: não informada',
      'Para cada linha da tabela, extraia:',
      '- ref_papel',
      '- ref_ext',
      '- descricao',
      '- fornecedor',
      '- data',
      '- pc',
      '- pv',
      '- qtd',
      'Também devolva categoria, colecao, fornecedor_geral e observacoes_ia.'
    ].join('\n');

    const response = await fetch('https://api.openai.com/v1/responses', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`
      },
      body: JSON.stringify({
        model: OPENAI_VISION_MODEL,
        input: [
          { role: 'system', content: [{ type: 'input_text', text: systemPrompt }] },
          {
            role: 'user',
            content: [
              { type: 'input_text', text: userPrompt },
              { type: 'input_image', image_url: `data:${mimeType || 'image/jpeg'};base64,${imageBase64}` }
            ]
          }
        ],
        text: {
          format: {
            type: 'json_schema',
            name: 'produto_importacao_foto',
            strict: true,
            schema: {
              type: 'object',
              additionalProperties: false,
              properties: {
                categoria: { type: 'string' },
                colecao: { type: 'string' },
                fornecedor_geral: { type: 'string' },
                observacoes_ia: { type: 'string' },
                itens: {
                  type: 'array',
                  items: {
                    type: 'object',
                    additionalProperties: false,
                    properties: {
                      ref_papel: { type: 'string' },
                      ref_ext: { type: 'string' },
                      descricao: { type: 'string' },
                      fornecedor: { type: 'string' },
                      data: { type: 'string' },
                      pc: { type: 'number' },
                      pv: { type: 'number' },
                      qtd: { type: 'integer' },
                      confianca: {
                        type: 'object',
                        additionalProperties: false,
                        properties: {
                          ref_papel: { type: 'string', enum: ['alta', 'media', 'baixa'] },
                          ref_ext: { type: 'string', enum: ['alta', 'media', 'baixa'] },
                          descricao: { type: 'string', enum: ['alta', 'media', 'baixa'] },
                          fornecedor: { type: 'string', enum: ['alta', 'media', 'baixa'] },
                          data: { type: 'string', enum: ['alta', 'media', 'baixa'] },
                          pc: { type: 'string', enum: ['alta', 'media', 'baixa'] },
                          pv: { type: 'string', enum: ['alta', 'media', 'baixa'] },
                          qtd: { type: 'string', enum: ['alta', 'media', 'baixa'] }
                        },
                        required: ['ref_papel', 'ref_ext', 'descricao', 'fornecedor', 'data', 'pc', 'pv', 'qtd']
                      },
                      observacoes: { type: 'string' }
                    },
                    required: ['ref_papel', 'ref_ext', 'descricao', 'fornecedor', 'data', 'pc', 'pv', 'qtd', 'confianca', 'observacoes']
                  }
                }
              },
              required: ['categoria', 'colecao', 'fornecedor_geral', 'observacoes_ia', 'itens']
            }
          }
        }
      })
    });

    const data = await response.json();
    if (!response.ok) {
      return res.status(response.status).json({ erro: data?.error?.message || 'Erro ao analisar imagem com IA' });
    }

    let parsed = null;
    if (typeof data.output_text === 'string' && data.output_text.trim()) {
      parsed = JSON.parse(data.output_text);
    } else {
      const txt = data.output?.flatMap(item => item.content || []).find(c => c.type === 'output_text')?.text;
      if (txt) parsed = JSON.parse(txt);
    }
    if (!parsed) return res.status(500).json({ erro: 'IA não retornou estrutura utilizável' });

    res.json({
      categoria: parsed.categoria || categoria || detectarCategoriaImportacao(parsed.observacoes_ia || ''),
      colecao: parsed.colecao || colecao || '',
      fornecedor: parsed.fornecedor_geral || '',
      observacoesIA: parsed.observacoes_ia || '',
      itens: Array.isArray(parsed.itens) ? parsed.itens : []
    });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.post('/api/produtos/importar-foto/analisar-texto', auth, async (req, res) => {
  try {
    if (!process.env.OPENAI_API_KEY) {
      return res.status(400).json({ erro: 'OPENAI_API_KEY não configurada no servidor' });
    }
    const { texto, categoria, colecao } = req.body || {};
    if (!String(texto || '').trim()) return res.status(400).json({ erro: 'Texto ou ditado não enviado' });

    const categoriasTexto = Object.values(IMPORT_PRODUTO_CONFIG)
      .map(cfg => `${cfg.categoria} => sufixo ${cfg.sufixo}, NCM ${cfg.ncm}`)
      .join('; ');
    const exemplosCorrecoes = await buscarCorrecoesImportacaoFoto(categoria, 12);
    const exemplosCorrecoesTexto = formatarCorrecoesParaPrompt(exemplosCorrecoes);

    const systemPrompt = [
      'Você transforma texto ditado ou digitado em linhas de cadastro de produtos de moda feminina.',
      'Devolva APENAS JSON válido no schema solicitado.',
      'Regras importantes:',
      '- O texto pode ser informal, com pontuação ruim, quebras de linha soltas ou frases como "próximo produto".',
      '- Cada produto deve virar uma linha em itens.',
      '- A referência interna do papel deve ir em ref_papel. Preserve apenas o número/código dito para a referência interna.',
      '- Se o usuário disser código, referência, ref ou papel, normalmente isso é ref_papel.',
      '- Se houver referência externa, coloque em ref_ext.',
      '- Os campos pc, pv e qtd devem ser números.',
      '- Preço de venda normalmente termina com centavos 90. Se o usuário disser apenas 159, considere 159.90.',
      '- Preço de custo pode ter centavos variados e deve ser lido exatamente como informado.',
      '- Quantidade é sempre número inteiro.',
      '- Se houver fornecedor geral, repita nos itens quando fizer sentido.',
      '- Se houver coleção geral, use em colecao. Caso contrário, use a coleção enviada pelo usuário se existir.',
      '- Extraia a data de cada linha no formato DD-MM ou DD/MM/AAAA quando informada.',
      '- Para texto digitado/ditado claro, use confiança alta. Se houver ambiguidade, use media ou baixa e explique em observacoes.',
      '- Categorias válidas: ' + categoriasTexto,
      exemplosCorrecoesTexto
        ? 'Exemplos reais de correções anteriores desta loja. Use como referência para abreviações, nomes de produtos e padrões de preço:\n' + exemplosCorrecoesTexto
        : ''
    ].join('\n');

    const userPrompt = [
      'Monte a importação de produtos a partir deste texto/ditado.',
      categoria ? `Categoria informada pelo usuário: ${categoria}` : 'Categoria informada pelo usuário: não informada',
      colecao ? `Coleção informada pelo usuário: ${colecao}` : 'Coleção informada pelo usuário: não informada',
      'Texto/ditado:',
      String(texto).trim()
    ].join('\n');

    const response = await fetch('https://api.openai.com/v1/responses', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`
      },
      body: JSON.stringify({
        model: OPENAI_VISION_MODEL,
        input: [
          { role: 'system', content: [{ type: 'input_text', text: systemPrompt }] },
          { role: 'user', content: [{ type: 'input_text', text: userPrompt }] }
        ],
        text: {
          format: {
            type: 'json_schema',
            name: 'produto_importacao_texto',
            strict: true,
            schema: schemaImportacaoProdutosIA()
          }
        }
      })
    });

    const data = await response.json();
    if (!response.ok) {
      return res.status(response.status).json({ erro: data?.error?.message || 'Erro ao analisar texto com IA' });
    }

    const parsed = extrairJsonRespostaOpenAI(data);
    if (!parsed) return res.status(500).json({ erro: 'IA não retornou estrutura utilizável' });

    res.json({
      categoria: parsed.categoria || categoria || detectarCategoriaImportacao(parsed.observacoes_ia || ''),
      colecao: parsed.colecao || colecao || '',
      fornecedor: parsed.fornecedor_geral || '',
      observacoesIA: parsed.observacoes_ia || '',
      itens: Array.isArray(parsed.itens) ? parsed.itens : []
    });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});
app.post('/api/produtos', auth, async (req, res) => {
  try {
    const p = req.body;
    const ncm = normalizarNCM(p.ncm);
    if (!ncm) {
      return res.status(400).json({ erro: 'NCM inválido. Informe exatamente 8 dígitos.' });
    }
    const conflitoCod = await pool.query(
      'SELECT id, status FROM produtos WHERE cod=$1 AND id<>$2 LIMIT 1',
      [p.cod, p.id]
    );
    if (conflitoCod.rows.length && conflitoCod.rows[0].status !== 'inativo') {
      return res.status(409).json({ erro: `Já existe um produto ativo com o código ${p.cod}.` });
    }
    const produtoId = conflitoCod.rows.length ? conflitoCod.rows[0].id : p.id;
    await pool.query(`INSERT INTO produtos (id,cod,nome,cat,cor,tam,colecao,data_entrada,custo,venda,est,estmin,descricao,foto,forn,ncm,cest,cfop,csosn,origem,unidade,cst_pis,cst_cofins,status,atualizado_em)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,NOW())
      ON CONFLICT (id) DO UPDATE SET cod=$2,nome=$3,cat=$4,cor=$5,tam=$6,colecao=$7,data_entrada=$8,custo=$9,venda=$10,est=$11,estmin=$12,descricao=$13,foto=$14,forn=$15,ncm=$16,cest=$17,cfop=$18,csosn=$19,origem=$20,unidade=$21,cst_pis=$22,cst_cofins=$23,status=$24,atualizado_em=NOW()`,
      [produtoId,p.cod,p.nome,p.cat,p.cor,p.tam,p.colecao,p.dataEntrada||null,p.custo||0,p.venda||0,p.est||0,p.estmin||5,p.descricao||p.desc,p.foto,p.forn,ncm,p.cest,p.cfop||'5102',p.csosn||'400',p.origem||'0',p.unidade||'UN',p.cstPis||'07',p.cstCofins||'07',p.status||'ativo']);
    res.json({ ok: true, reativado: produtoId !== p.id });
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
    const { produtoId, produtoCod, tipo, dataInicio, dataFim, limit } = req.query;
    let where = 'WHERE 1=1';
    const params = [];
    let i = 1;
    if (produtoId) { where += ` AND produto_id=$${i++}`; params.push(produtoId); }
    if (produtoCod) { where += ` AND produto_cod ILIKE $${i++}`; params.push('%' + produtoCod + '%'); }
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
    await client.query(`ALTER TABLE clientes ADD COLUMN IF NOT EXISTS ie TEXT DEFAULT ''`);
    await client.query(`INSERT INTO clientes (id,nome,tipo,cpf,cnpj,ie,nasc,tel,email,ig,tam,obs,total_compras,ult_compra,status)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
      ON CONFLICT (id) DO UPDATE SET nome=$2,tipo=$3,cpf=$4,cnpj=$5,ie=$6,nasc=$7,tel=$8,email=$9,ig=$10,tam=$11,obs=$12,total_compras=$13,ult_compra=$14,status=$15`,
      [c.id,c.nome,c.tipo||'PF',c.cpf,c.cnpj,c.ie||'',c.nasc||null,c.tel,c.email,c.ig,c.tam,c.obs,c.totalCompras||c.total_compras||0,c.ultCompra||c.ult_compra||null,c.status||'ativo']);
    // Salva endereços
    if (c.enderecos !== undefined) {
      await client.query('DELETE FROM enderecos_cliente WHERE cliente_id=$1', [c.id]);
      for (const e of (c.enderecos||[])) {
        const ufEndereco = (e.uf || e.estado || '').toUpperCase();
        await client.query(`INSERT INTO enderecos_cliente (id,cliente_id,tipo,cep,logradouro,numero,complemento,bairro,cidade,estado,uf,principal)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
          [e.id||uid(),c.id,e.tipo||'Residencial',e.cep,e.logradouro,e.numero,e.complemento,e.bairro,e.cidade,ufEndereco,ufEndereco,e.principal||false]);
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
    const { de, ate, status, limit, offset, vendedor_id } = req.query;
    let where = ['1=1'];
    let params = [];
    let i = 1;
    if (de) { where.push(`DATE(data) >= $${i++}`); params.push(de); }
    if (ate) { where.push(`DATE(data) <= $${i++}`); params.push(ate); }
    if (status) { where.push(`v.status = $${i++}`); params.push(status); }
    if (vendedor_id) { where.push(`v.vendedor_id = $${i++}`); params.push(vendedor_id); }
    const sql = `
      SELECT v.*,
        MAX(c.cpf) as cpf, MAX(c.cnpj) as cnpj, MAX(c.tel) as cliente_tel, MAX(c.email) as cliente_email,
        MAX(e.cep) as endereco_cep, MAX(e.logradouro) as endereco_logradouro, MAX(e.numero) as endereco_numero,
        MAX(e.complemento) as endereco_complemento, MAX(e.bairro) as endereco_bairro, MAX(e.cidade) as endereco_cidade,
        COALESCE(MAX(NULLIF(e.uf, '')), MAX(NULLIF(e.estado, ''))) as endereco_uf,
        COALESCE(json_agg(DISTINCT jsonb_build_object('id',vi.id,'nome',vi.nome,'cod',vi.cod,'preco',vi.preco,'qty',vi.qty,'tipo',vi.tipo)) FILTER (WHERE vi.id IS NOT NULL),'[]') as itens,
        COALESCE(json_agg(DISTINCT jsonb_build_object('tipo',vp.tipo,'valor',vp.valor,'parcelas',vp.parcelas,'vl_parcela',vp.vl_parcela,'detalhe',vp.detalhe,'cheques_json',vp.cheques_json)) FILTER (WHERE vp.id IS NOT NULL),'[]') as pgto_itens
      FROM vendas v
      LEFT JOIN clientes c ON c.id = v.cliente_id
      LEFT JOIN enderecos_cliente e ON e.cliente_id = v.cliente_id AND e.principal = true
      LEFT JOIN venda_itens vi ON vi.venda_id=v.id
      LEFT JOIN venda_pagamentos vp ON vp.venda_id=v.id
      WHERE ${where.join(' AND ')}
      GROUP BY v.id ORDER BY v.data DESC
      LIMIT ${parseInt(limit)||200} OFFSET ${parseInt(offset)||0}`;
    const r = await pool.query(sql, params);
    const vendas = await sincronizarSituacaoNFeDasVendas(r.rows);
    res.json(vendas);
  } catch (err) { res.status(500).json({ erro: err.message }); }
});
app.post('/api/vendas', auth, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const v = req.body;
    const insertResult = await client.query(`INSERT INTO vendas (id,num,data,cliente_id,cliente_nome,vendedor_id,vendedor_nome,canal,subtotal,desconto,desc_pct,desconto_manual,credito,tot,credito_gerado,pag,obs,tipo,status)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
      ON CONFLICT (id) DO NOTHING RETURNING id`,
      [v.id,v.num,v.data,v.clienteId,v.clienteNome,v.vendedorId,v.vendedorNome,v.canal,v.sub||v.subtotal,v.desc||v.desconto||0,v.descPct||v.desc_pct||0,v.descManual||v.descontoManual||v.desconto_manual||0,v.credito||0,v.tot,v.creditoGerado||0,v.pag,v.obs,v.tipo||'venda',v.status||'pago']);
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

// QZ TRAY — assinatura das chamadas para evitar prompts de "Untrusted website"
app.get('/api/qz/status', auth, (req, res) => {
  res.json({ configurado: qzTrayConfigurado() });
});

app.get('/api/qz/certificate', auth, (req, res) => {
  if (!QZ_CERTIFICATE) return res.status(503).type('text/plain').send('Certificado do QZ Tray não configurado.');
  res.type('text/plain').send(QZ_CERTIFICATE);
});

app.post('/api/qz/sign', auth, (req, res) => {
  if (!qzTrayConfigurado()) return res.status(503).type('text/plain').send('Assinatura do QZ Tray não configurada.');
  const request = req.body?.request;
  if (!request || typeof request !== 'string') {
    return res.status(400).type('text/plain').send('Conteúdo para assinatura não informado.');
  }
  try {
    const signer = crypto.createSign('RSA-SHA512');
    signer.update(request, 'utf8');
    signer.end();
    const key = QZ_PRIVATE_KEY_PASSPHRASE
      ? { key: QZ_PRIVATE_KEY, passphrase: QZ_PRIVATE_KEY_PASSPHRASE }
      : QZ_PRIVATE_KEY;
    res.type('text/plain').send(signer.sign(key, 'base64'));
  } catch (err) {
    console.error('Erro ao assinar requisição do QZ Tray:', err);
    res.status(500).type('text/plain').send('Erro ao assinar requisição do QZ Tray.');
  }
});

// VALES — Buscar detalhes de uma funcionária no mês (para romaneio)
app.get('/api/vales/funcionaria', auth, async (req, res) => {
  try {
    const { funcionarioId, mes } = req.query;
    if (!funcionarioId || !mes) return res.status(400).json({ erro: 'Dados incompletos' });

    const r = await pool.query(
      `SELECT v.*,
        COALESCE(
          json_agg(
            json_build_object(
              'id', vi.id,
              'produto_nome', vi.produto_nome,
              'produto_cod', vi.produto_cod,
              'qty', vi.qty,
              'preco_cheio', vi.preco_cheio,
              'preco_desc', vi.preco_desc
            ) ORDER BY vi.produto_nome
          ) FILTER (WHERE vi.id IS NOT NULL),
          '[]'
        ) AS itens
       FROM vales_funcionarios v
       LEFT JOIN vale_itens vi ON vi.vale_id = v.id
       WHERE v.funcionario_id = $1
         AND v.mes_desconto IS NOT NULL
         AND (
           (COALESCE(v.parcelas,1) = 1 AND v.mes_desconto = $2)
           OR
           (COALESCE(v.parcelas,1) > 1
            AND TO_DATE(v.mes_desconto || '-01', 'YYYY-MM-DD') <= TO_DATE($2 || '-01', 'YYYY-MM-DD')
            AND TO_DATE($2 || '-01', 'YYYY-MM-DD') <=
                (TO_DATE(v.mes_desconto || '-01', 'YYYY-MM-DD') + ((COALESCE(v.parcelas,1) - 1) * INTERVAL '1 month'))
           )
         )
       GROUP BY v.id
       ORDER BY v.tipo, v.criado_em`,
      [funcionarioId, mes]
    );
    res.json({ vales: r.rows });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// VALES — Listar por funcionário e mês
app.get('/api/vales', auth, async (req, res) => {
  try {
    const { funcionarioId, mes } = req.query;
    let conditions = ['1=1'];
    const params = [];
    let i = 1;

    if (funcionarioId) {
      conditions.push(`v.funcionario_id=$${i++}`);
      params.push(funcionarioId);
    }

    if (mes) {
      // Histórico mensal: mostra o vale em qualquer mês coberto pelo parcelamento
      conditions.push(`(
        v.mes_desconto IS NOT NULL
        AND (
          (COALESCE(v.parcelas,1) = 1 AND v.mes_desconto = $${i})
          OR
          (COALESCE(v.parcelas,1) > 1
           AND TO_DATE(v.mes_desconto || '-01', 'YYYY-MM-DD') <= TO_DATE($${i} || '-01', 'YYYY-MM-DD')
           AND TO_DATE($${i} || '-01', 'YYYY-MM-DD') <=
               (TO_DATE(v.mes_desconto || '-01', 'YYYY-MM-DD') + ((COALESCE(v.parcelas,1) - 1) * INTERVAL '1 month'))
          )
        )
      )`);
      params.push(mes);
      i++;
    }

    const where = 'WHERE ' + conditions.join(' AND ');

    const r = await pool.query(
      `SELECT v.*,
        COALESCE(
          json_agg(
            json_build_object(
              'id', vi.id,
              'produto_id', vi.produto_id,
              'produto_nome', vi.produto_nome,
              'produto_cod', vi.produto_cod,
              'qty', vi.qty,
              'preco_cheio', vi.preco_cheio,
              'preco_desc', vi.preco_desc
            ) ORDER BY vi.produto_nome
          ) FILTER (WHERE vi.id IS NOT NULL),
          '[]'
        ) AS itens
       FROM vales_funcionarios v
       LEFT JOIN vale_itens vi ON vi.vale_id = v.id
       ${where}
       GROUP BY v.id
       ORDER BY v.criado_em DESC`,
      params
    );

    const total = r.rows.reduce((a, v) => a + parseFloat(v.valor), 0);
    res.json({ vales: r.rows, total: Math.round(total * 100) / 100 });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// VALES — Resumo mensal por funcionário
app.get('/api/vales/resumo', auth, async (req, res) => {
  try {
    const { mes } = req.query;
    const mesFiltro = mes || new Date().toISOString().slice(0,7);
    const r = await pool.query(
      `SELECT funcionario_id, funcionario_nome,
        SUM(CASE WHEN tipo='dinheiro' THEN valor ELSE 0 END) as total_dinheiro,
        SUM(CASE WHEN tipo='roupa' THEN
          CASE WHEN COALESCE(parcelas,1) > 1 THEN vl_parcela ELSE valor END
        ELSE 0 END) as total_roupa,
        SUM(CASE
          WHEN tipo='dinheiro' THEN valor
          WHEN tipo='roupa' AND COALESCE(parcelas,1) > 1 THEN vl_parcela
          ELSE valor
        END) as total,
        COUNT(*) as qtd,
        COALESCE(
          json_agg(
            json_build_object(
              'tipo', tipo,
              'descricao', descricao,
              'valor', CASE
                WHEN tipo='roupa' AND COALESCE(parcelas,1) > 1 THEN vl_parcela
                ELSE valor
              END,
              'parcela_atual', CASE
                WHEN COALESCE(parcelas,1) > 1 THEN COALESCE(parcelas_pagas,0) + 1
                ELSE NULL
              END,
              'total_parcelas', COALESCE(parcelas,1)
            ) ORDER BY criado_em
          ) FILTER (WHERE id IS NOT NULL),
          '[]'
        ) as detalhes
       FROM vales_funcionarios
       WHERE status != 'descontado'
         AND mes_desconto IS NOT NULL
         AND (
           (COALESCE(parcelas, 1) = 1 AND mes_desconto = $1)
           OR
           (COALESCE(parcelas, 1) > 1
            AND TO_DATE(mes_desconto || '-01', 'YYYY-MM-DD')
                + (COALESCE(parcelas_pagas, 0) * INTERVAL '1 month')
                = TO_DATE($1 || '-01', 'YYYY-MM-DD')
           )
         )
       GROUP BY funcionario_id, funcionario_nome
       ORDER BY total DESC`,
      [mesFiltro]
    );
    res.json(r.rows);
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// VALES — Todos os pendentes expandidos por parcela futura
app.get('/api/vales/pendentes', auth, async (req, res) => {
  try {
    const mesAtual = new Date().toISOString().slice(0, 7);

    // Busca todos os vales pendentes
    const r = await pool.query(
      `SELECT id, funcionario_id, funcionario_nome, tipo, valor,
              parcelas, parcelas_pagas, vl_parcela, mes_desconto
       FROM vales_funcionarios
       WHERE status != 'descontado'
         AND mes_desconto IS NOT NULL
       ORDER BY mes_desconto, funcionario_nome`
    );

    // Para cada vale, calcula os meses de parcelas ainda pendentes
    const resultado = {};
    for (const v of r.rows) {
      const totalParcelas = parseInt(v.parcelas) || 1;
      const pagas = parseInt(v.parcelas_pagas) || 0;
      const vlParcela = totalParcelas > 1 && parseFloat(v.vl_parcela) > 0
        ? parseFloat(v.vl_parcela)
        : parseFloat(v.valor);

      const [mdAno, mdMes] = v.mes_desconto.split('-').map(Number);

      // Itera apenas pelas parcelas ainda não pagas
      for (let i = pagas; i < totalParcelas; i++) {
        const data = new Date(mdAno, mdMes - 1 + i, 1);
        const mesParcela = data.getFullYear() + '-' + String(data.getMonth() + 1).padStart(2, '0');

        // Só mostra do mês atual em diante
        if (mesParcela < mesAtual) continue;

        if (!resultado[mesParcela]) resultado[mesParcela] = {};
        const key = v.funcionario_id;
        if (!resultado[mesParcela][key]) {
          resultado[mesParcela][key] = {
            funcionario_id: v.funcionario_id,
            funcionario_nome: v.funcionario_nome,
            mes_desconto: mesParcela,
            total_dinheiro: 0,
            total_roupa: 0,
            total: 0
          };
        }
        if (v.tipo === 'dinheiro') {
          resultado[mesParcela][key].total_dinheiro += vlParcela;
        } else {
          resultado[mesParcela][key].total_roupa += vlParcela;
        }
        resultado[mesParcela][key].total += vlParcela;
      }
    }

    // Converte para array ordenado
    const rows = [];
    Object.keys(resultado).sort().forEach(mes => {
      Object.values(resultado[mes]).forEach(item => rows.push(item));
    });

    res.json(rows);
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// VALES — Registrar vale em dinheiro
app.post('/api/vales', auth, async (req, res) => {
  try {
    const { id, funcionarioId, funcionarioNome, valor, tipo, descricao, mes, vendaId } = req.body;
    const mesDesconto = calcularMesDesconto('dinheiro', new Date());
    await pool.query(
      `INSERT INTO vales_funcionarios
         (id, funcionario_id, funcionario_nome, valor, tipo, descricao, mes, venda_id, mes_desconto)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [id, funcionarioId, funcionarioNome, valor, tipo||'dinheiro', descricao||'', mes, vendaId||null, mesDesconto]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.post('/api/vales/roupa', auth, async (req, res) => {
  const client = await pool.connect();
  try {
    const { id, funcionarioId, funcionarioNome, mes, parcelas, itens } = req.body;
    if (!id || !funcionarioId || !mes || !itens || !itens.length) {
      return res.status(400).json({ erro: 'Dados incompletos' });
    }
    const parc = parseInt(parcelas) || 1;
    const total = itens.reduce((s, i) => s + (parseFloat(i.precoDesc) * i.qty), 0);
    const vlParcela = Math.round((total / parc) * 100) / 100;
    const descParc = parc > 1
      ? ` (${parc}x de R$ ${vlParcela.toFixed(2).replace('.', ',')})`
      : '';
    const mesDesconto = calcularMesDesconto('roupa', new Date());
    await client.query('BEGIN');
    await client.query(
      `INSERT INTO vales_funcionarios
         (id, funcionario_id, funcionario_nome, valor, tipo, descricao, mes, parcelas, vl_parcela, status, mes_desconto)
       VALUES ($1,$2,$3,$4,'roupa',$5,$6,$7,$8,'pendente',$9)`,
      [id, funcionarioId, funcionarioNome, total, 'Vale roupa' + descParc, mes, parc, vlParcela, mesDesconto]
    );
    for (const item of itens) {
      const itemId = require('crypto').randomUUID();
      await client.query(
        `INSERT INTO vale_itens (id, vale_id, produto_id, produto_nome, produto_cod, qty, preco_cheio, preco_desc)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [itemId, id, item.produtoId, item.produtoNome, item.produtoCod, item.qty, item.precoCheio, item.precoDesc]
      );
      await client.query(
        'UPDATE produtos SET est = est - $1, atualizado_em = NOW() WHERE id = $2',
        [item.qty, item.produtoId]
      );
    }
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ erro: err.message });
  } finally { client.release(); }
});

// VALES — Descontar todos os vales pendentes de uma funcionária no mês
app.patch('/api/vales/descontar-funcionaria', auth, async (req, res) => {
  try {
    const { funcionarioId, mes } = req.body;
    if (!funcionarioId || !mes) return res.status(400).json({ erro: 'Dados incompletos' });

    const r = await pool.query(
      `SELECT id, parcelas, parcelas_pagas, mes_desconto FROM vales_funcionarios
       WHERE funcionario_id = $1 AND status != 'descontado'`,
      [funcionarioId]
    );

    let atualizados = 0;
    for (const vale of r.rows) {
      const totalParcelas = parseInt(vale.parcelas) || 1;
      const pagas = parseInt(vale.parcelas_pagas) || 0;
      const [mdAno, mdMes] = vale.mes_desconto.split('-').map(Number);

      // Calcula qual mês é o correto para a próxima parcela deste vale
      const dataEsperada = new Date(mdAno, mdMes - 1 + pagas, 1);
      const mesEsperado = dataEsperada.getFullYear() + '-' + String(dataEsperada.getMonth() + 1).padStart(2, '0');

      // Só desconta se o mês bate — ignora silenciosamente os que não batem
      if (mesEsperado !== mes) continue;

      const novasPagas = pagas + 1;
      const novoStatus = novasPagas >= totalParcelas ? 'descontado' : 'pendente';
      await pool.query(
        'UPDATE vales_funcionarios SET parcelas_pagas=$1, status=$2 WHERE id=$3',
        [novasPagas, novoStatus, vale.id]
      );
      atualizados++;
    }

    res.json({ ok: true, atualizados });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// VALES — Marcar como descontado
app.patch('/api/vales/:id/descontar', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT parcelas, parcelas_pagas FROM vales_funcionarios WHERE id=$1', [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ erro: 'Vale não encontrado' });
    const { parcelas, parcelas_pagas } = r.rows[0];
    const totalParcelas = parseInt(parcelas) || 1;
    const pagas = parseInt(parcelas_pagas) || 0;
    const novasPagas = pagas + 1;
    const novoStatus = novasPagas >= totalParcelas ? 'descontado' : 'pendente';
    await pool.query(
      'UPDATE vales_funcionarios SET parcelas_pagas=$1, status=$2 WHERE id=$3',
      [novasPagas, novoStatus, req.params.id]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// VALES — Excluir
app.delete('/api/vales/:id', auth, async (req, res) => {
  try {
    await pool.query(`DELETE FROM vales_funcionarios WHERE id=$1`, [req.params.id]);
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
        FROM vendas WHERE TO_CHAR(data,'YYYY-MM')=$1 AND status!='cancelada' AND (tipo IS NULL OR tipo NOT IN ('vale_funcionaria'))`, [mes]),
      pool.query(`SELECT DATE(data) as dia,SUM(tot) as total,COUNT(*) as qtd FROM vendas
        WHERE TO_CHAR(data,'YYYY-MM')=$1 AND status!='cancelada' AND (tipo IS NULL OR tipo NOT IN ('vale_funcionaria')) GROUP BY DATE(data) ORDER BY dia`, [mes]),
      pool.query(`SELECT vendedor_nome,COUNT(*) as qtd,SUM(tot) as total FROM vendas
        WHERE TO_CHAR(data,'YYYY-MM')=$1 AND status!='cancelada' AND (tipo IS NULL OR tipo NOT IN ('vale_funcionaria')) GROUP BY vendedor_nome ORDER BY total DESC`, [mes]),
      pool.query(`SELECT vi.nome,SUM(vi.qty) as qty,SUM(vi.preco*vi.qty) as receita FROM venda_itens vi
        JOIN vendas v ON v.id=vi.venda_id WHERE TO_CHAR(v.data,'YYYY-MM')=$1 AND v.status!='cancelada' AND vi.tipo!='devolvido' AND (v.tipo IS NULL OR v.tipo NOT IN ('vale_funcionaria'))
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
    const { tipo, status, mes, de, ate } = req.query;
    let where = ['1=1'];
    let params = [];
    let i = 1;
    if (tipo) { where.push(`tipo=$${i++}`); params.push(tipo); }
    if (status) { where.push(`status=$${i++}`); params.push(status); }
    if (mes) { where.push(`TO_CHAR(data_compensacao,'YYYY-MM')=$${i++}`); params.push(mes); }
    if (de) { where.push(`data_compensacao >= $${i++}`); params.push(de); }
    if (ate) { where.push(`data_compensacao <= $${i++}`); params.push(ate); }
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

async function resumoOperacionalDia(data) {
  const vendas = await pool.query(
    `SELECT id, num, cliente_nome, vendedor_nome, canal, subtotal, desconto, credito, tot, pag,
            credito_gerado, nfe_id, nfce_id, status, tipo
     FROM vendas
     WHERE DATE(data AT TIME ZONE 'America/Sao_Paulo') = $1
       AND status != 'cancelada'
       AND (tipo IS NULL OR tipo NOT IN ('vale_funcionaria'))`,
    [data]
  );
  const pagamentos = await pool.query(
    `SELECT vp.tipo, vp.valor, vp.parcelas, vp.troco
     FROM venda_pagamentos vp
     JOIN vendas v ON v.id = vp.venda_id
     WHERE DATE(v.data AT TIME ZONE 'America/Sao_Paulo') = $1
       AND v.status != 'cancelada'
       AND (v.tipo IS NULL OR v.tipo NOT IN ('vale_funcionaria'))`,
    [data]
  );
  const movimentos = await pool.query(
    `SELECT cm.tipo, cm.valor
     FROM caixa_movimentos cm
     JOIN caixa c ON c.id = cm.caixa_id
     WHERE c.data = $1`,
    [data]
  );

  const formas = {
    dinheiro: { chave: 'dinheiro', label: 'Dinheiro', sistema: 0, contado: 0 },
    pix: { chave: 'pix', label: 'PIX', sistema: 0, contado: 0 },
    debito: { chave: 'debito', label: 'Débito', sistema: 0, contado: 0 },
    credito: { chave: 'credito', label: 'Crédito', sistema: 0, contado: 0 },
    cheque: { chave: 'cheque', label: 'Cheque à vista', sistema: 0, contado: 0 },
    cheque_pre: { chave: 'cheque_pre', label: 'Cheque pré-datado', sistema: 0, contado: 0 },
    outros: { chave: 'outros', label: 'Outros', sistema: 0, contado: 0 }
  };

  let troco = 0;
  pagamentos.rows.forEach(p => {
    const tipo = String(p.tipo || '').toLowerCase();
    const valor = parseFloat(p.valor || 0);
    troco += parseFloat(p.troco || 0);
    if (tipo === 'dinheiro') formas.dinheiro.sistema += valor;
    else if (tipo === 'pix') formas.pix.sistema += valor;
    else if (tipo === 'debito') formas.debito.sistema += valor;
    else if (tipo === 'credito') formas.credito.sistema += valor;
    else if (tipo === 'cheque') formas.cheque.sistema += valor;
    else if (tipo === 'cheque_pre') formas.cheque_pre.sistema += valor;
    else formas.outros.sistema += valor;
  });
  formas.dinheiro.sistema = Math.max(0, formas.dinheiro.sistema - troco);

  const entradas = movimentos.rows
    .filter(m => m.tipo === 'entrada')
    .reduce((acc, m) => acc + parseFloat(m.valor || 0), 0);
  const saidas = movimentos.rows
    .filter(m => m.tipo === 'saida')
    .reduce((acc, m) => acc + parseFloat(m.valor || 0), 0);
  formas.dinheiro.sistema += entradas - saidas;

  const totalVendas = vendas.rows.reduce((acc, v) => acc + parseFloat(v.tot || 0) + parseFloat(v.credito_gerado || 0), 0);
  const totalSistema = Object.values(formas).reduce((acc, f) => acc + f.sistema, 0);
  return {
    data,
    vendas: vendas.rows.length,
    totalVendas: Math.round(totalVendas * 100) / 100,
    totalSistema: Math.round(totalSistema * 100) / 100,
    troco: Math.round(troco * 100) / 100,
    movimentos: { entradas: Math.round(entradas * 100) / 100, saidas: Math.round(saidas * 100) / 100 },
    formas: Object.values(formas).map(f => ({ ...f, sistema: Math.round(f.sistema * 100) / 100 }))
  };
}

function pequenoItem(row, campos) {
  const item = {};
  campos.forEach(c => item[c] = row[c]);
  return item;
}

// FINANCEIRO — CAIXA
app.get('/api/financeiro/caixa/hoje', auth, async (req, res) => {
  try {
    const hoje = dataLocalISO();
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

app.get('/api/financeiro/fechamento', auth, async (req, res) => {
  try {
    const data = req.query.data || dataLocalISO();
    const resumo = await resumoOperacionalDia(data);
    const caixa = await pool.query(`SELECT * FROM caixa WHERE data=$1`, [data]);
    const fechamento = caixa.rows[0] || null;
    const detalhes = fechamento?.detalhes || {};
    if (detalhes?.formas) {
      resumo.formas = resumo.formas.map(f => ({
        ...f,
        contado: Number(detalhes.formas[f.chave] || 0),
        diferenca: Math.round((Number(detalhes.formas[f.chave] || 0) - f.sistema) * 100) / 100
      }));
    }
    res.json({ data, resumo, fechamento });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.post('/api/financeiro/fechamento', auth, async (req, res) => {
  try {
    const data = req.body.data || dataLocalISO();
    const valores = req.body.valores || {};
    const observacao = req.body.observacao || '';
    const resumo = await resumoOperacionalDia(data);
    const totalContado = resumo.formas.reduce((acc, f) => acc + (parseFloat(valores[f.chave] || 0) || 0), 0);
    const totalSistema = resumo.totalSistema;
    const diferenca = Math.round((totalContado - totalSistema) * 100) / 100;
    const detalhes = {
      formas: resumo.formas.reduce((acc, f) => {
        acc[f.chave] = Math.round((parseFloat(valores[f.chave] || 0) || 0) * 100) / 100;
        return acc;
      }, {}),
      resumo,
      fechadoPor: req.user?.nome || req.user?.id || null
    };
    await pool.query(
      `INSERT INTO caixa (id, data, valor_abertura, valor_fechamento, valor_sistema, diferenca, status, observacao, detalhes, fechado_por, fechado_em)
       VALUES ($1,$2,0,$3,$4,$5,'fechado',$6,$7,$8,NOW())
       ON CONFLICT (data) DO UPDATE SET
         valor_fechamento=EXCLUDED.valor_fechamento,
         valor_sistema=EXCLUDED.valor_sistema,
         diferenca=EXCLUDED.diferenca,
         observacao=EXCLUDED.observacao,
         detalhes=EXCLUDED.detalhes,
         fechado_por=EXCLUDED.fechado_por,
         fechado_em=NOW(),
         status='fechado'`,
      [uid(), data, Math.round(totalContado * 100) / 100, totalSistema, diferenca, observacao, detalhes, req.user?.nome || req.user?.id || null]
    );
    res.json({ ok: true, data, resumo, totalContado: Math.round(totalContado * 100) / 100, totalSistema, diferenca });
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

app.get('/api/pendencias', auth, async (req, res) => {
  try {
    const hoje = dataLocalISO();
    const [
      estoqueBaixo,
      estoqueZerado,
      semNcm,
      semFornecedor,
      vendasSemNota,
      contasAtrasadas,
      contasVencendo,
      chequesVencendo,
      valesPendentes
    ] = await Promise.all([
      pool.query(`SELECT cod,nome,est,estmin FROM produtos WHERE status='ativo' AND COALESCE(est,0) > 0 AND COALESCE(est,0) <= COALESCE(estmin,0) ORDER BY est ASC, nome LIMIT 8`),
      pool.query(`SELECT cod,nome,est FROM produtos WHERE status='ativo' AND COALESCE(est,0) <= 0 ORDER BY nome LIMIT 8`),
      pool.query(`SELECT cod,nome,ncm FROM produtos WHERE status='ativo' AND (COALESCE(ncm,'') = '' OR regexp_replace(ncm,'\\D','','g') !~ '^\\d{8}$') ORDER BY atualizado_em DESC LIMIT 8`),
      pool.query(`SELECT cod,nome,forn FROM produtos WHERE status='ativo' AND COALESCE(forn,'') = '' ORDER BY atualizado_em DESC LIMIT 8`),
      pool.query(
        `SELECT num,cliente_nome,tot,data
         FROM vendas
         WHERE status != 'cancelada'
           AND (tipo IS NULL OR tipo NOT IN ('vale_funcionaria'))
           AND COALESCE(nfe_id,'') = ''
           AND COALESCE(nfce_id,'') = ''
           AND data >= NOW() - INTERVAL '30 days'
         ORDER BY data DESC LIMIT 8`
      ),
      pool.query(`SELECT descricao,valor,vencimento FROM contas_pagar WHERE pago=false AND vencimento < $1 ORDER BY vencimento ASC LIMIT 8`, [hoje]),
      pool.query(`SELECT descricao,valor,vencimento FROM contas_pagar WHERE pago=false AND vencimento >= $1 AND vencimento <= ($1::date + INTERVAL '7 days') ORDER BY vencimento ASC LIMIT 8`, [hoje]),
      pool.query(`SELECT nome,valor,data_compensacao,banco FROM cheques WHERE status='pendente' AND data_compensacao <= ($1::date + INTERVAL '7 days') ORDER BY data_compensacao ASC LIMIT 8`, [hoje]),
      pool.query(`SELECT funcionario_nome,valor,tipo,mes_desconto FROM vales_funcionarios WHERE status='pendente' ORDER BY criado_em DESC LIMIT 8`)
    ]);

    const grupos = [
      {
        chave: 'estoque_baixo',
        titulo: 'Estoque baixo',
        severidade: estoqueBaixo.rows.length ? 'aviso' : 'ok',
        resumo: estoqueBaixo.rows.length ? 'Produtos abaixo ou no mínimo configurado.' : 'Nenhum produto em estoque baixo.',
        total: estoqueBaixo.rows.length,
        itens: estoqueBaixo.rows.map(r => pequenoItem(r, ['cod', 'nome', 'est', 'estmin']))
      },
      {
        chave: 'estoque_zerado',
        titulo: 'Estoque zerado',
        severidade: estoqueZerado.rows.length ? 'critico' : 'ok',
        resumo: estoqueZerado.rows.length ? 'Produtos ativos sem estoque.' : 'Nenhum produto zerado.',
        total: estoqueZerado.rows.length,
        itens: estoqueZerado.rows.map(r => pequenoItem(r, ['cod', 'nome', 'est']))
      },
      {
        chave: 'fiscal_sem_ncm',
        titulo: 'Produtos sem NCM válido',
        severidade: semNcm.rows.length ? 'critico' : 'ok',
        resumo: semNcm.rows.length ? 'Pode bloquear emissão de nota.' : 'NCM dos produtos ativos está ok.',
        total: semNcm.rows.length,
        itens: semNcm.rows.map(r => pequenoItem(r, ['cod', 'nome', 'ncm']))
      },
      {
        chave: 'sem_fornecedor',
        titulo: 'Produtos sem fornecedor',
        severidade: semFornecedor.rows.length ? 'aviso' : 'ok',
        resumo: semFornecedor.rows.length ? 'Ajuda a rastrear entradas e reposição.' : 'Produtos ativos possuem fornecedor.',
        total: semFornecedor.rows.length,
        itens: semFornecedor.rows.map(r => pequenoItem(r, ['cod', 'nome', 'forn']))
      },
      {
        chave: 'vendas_sem_nota',
        titulo: 'Vendas recentes sem NF-e/NFC-e',
        severidade: vendasSemNota.rows.length ? 'aviso' : 'ok',
        resumo: vendasSemNota.rows.length ? 'Vendas pagas dos últimos 30 dias sem nota vinculada.' : 'Sem vendas recentes pendentes de nota.',
        total: vendasSemNota.rows.length,
        itens: vendasSemNota.rows.map(r => pequenoItem(r, ['num', 'cliente_nome', 'tot', 'data']))
      },
      {
        chave: 'contas_atrasadas',
        titulo: 'Contas atrasadas',
        severidade: contasAtrasadas.rows.length ? 'critico' : 'ok',
        resumo: contasAtrasadas.rows.length ? 'Contas a pagar vencidas.' : 'Nenhuma conta atrasada.',
        total: contasAtrasadas.rows.length,
        itens: contasAtrasadas.rows.map(r => pequenoItem(r, ['descricao', 'valor', 'vencimento']))
      },
      {
        chave: 'contas_vencendo',
        titulo: 'Contas vencendo em 7 dias',
        severidade: contasVencendo.rows.length ? 'aviso' : 'ok',
        resumo: contasVencendo.rows.length ? 'Contas próximas do vencimento.' : 'Sem contas vencendo nos próximos 7 dias.',
        total: contasVencendo.rows.length,
        itens: contasVencendo.rows.map(r => pequenoItem(r, ['descricao', 'valor', 'vencimento']))
      },
      {
        chave: 'cheques_vencendo',
        titulo: 'Cheques para compensar',
        severidade: chequesVencendo.rows.length ? 'aviso' : 'ok',
        resumo: chequesVencendo.rows.length ? 'Cheques pendentes com compensação próxima.' : 'Sem cheques para compensar nos próximos 7 dias.',
        total: chequesVencendo.rows.length,
        itens: chequesVencendo.rows.map(r => pequenoItem(r, ['nome', 'valor', 'data_compensacao', 'banco']))
      },
      {
        chave: 'vales_pendentes',
        titulo: 'Vales pendentes',
        severidade: valesPendentes.rows.length ? 'aviso' : 'ok',
        resumo: valesPendentes.rows.length ? 'Vales ainda não fechados/descontados.' : 'Sem vales pendentes.',
        total: valesPendentes.rows.length,
        itens: valesPendentes.rows.map(r => pequenoItem(r, ['funcionario_nome', 'valor', 'tipo', 'mes_desconto']))
      }
    ];

    res.json({
      data: hoje,
      resumo: {
        criticos: grupos.filter(g => g.severidade === 'critico').length,
        avisos: grupos.filter(g => g.severidade === 'aviso').length,
        ok: grupos.filter(g => g.severidade === 'ok').length
      },
      grupos
    });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.get('/api/pre-producao/checklist', auth, async (req, res) => {
  try {
    const [
      funcionarios,
      administradores,
      produtos,
      produtosSemNcm,
      categorias,
      clientesSemCpf,
      backupEmail,
      blingToken
    ] = await Promise.all([
      pool.query(`SELECT COUNT(*)::int AS total FROM funcionarios WHERE status='ativo'`),
      pool.query(`SELECT COUNT(*)::int AS total FROM funcionarios WHERE status='ativo' AND cargo='Administrador'`),
      pool.query(`SELECT COUNT(*)::int AS total FROM produtos WHERE status='ativo'`),
      pool.query(`SELECT COUNT(*)::int AS total FROM produtos WHERE status='ativo' AND (COALESCE(ncm,'') = '' OR regexp_replace(ncm,'\\D','','g') !~ '^\\d{8}$')`),
      pool.query(`SELECT COUNT(*)::int AS total FROM categorias`),
      pool.query(`SELECT COUNT(*)::int AS total FROM clientes WHERE status='ativo' AND tipo='PF' AND COALESCE(cpf,'') = ''`),
      pool.query(`SELECT valor FROM configuracoes WHERE chave='backup_email'`),
      pool.query(`SELECT expires_at FROM bling_tokens WHERE id=1`)
    ]);
    const tokenValido = !!blingToken.rows[0]?.expires_at && new Date(blingToken.rows[0].expires_at) > new Date();
    const emailBackup = backupEmail.rows[0]?.valor || null;
    const itens = [
      {
        titulo: 'Funcionários ativos',
        status: funcionarios.rows[0].total > 0 ? 'ok' : 'critico',
        obrigatorio: true,
        detalhe: `${funcionarios.rows[0].total} funcionário(s) ativo(s).`
      },
      {
        titulo: 'Administrador configurado',
        status: administradores.rows[0].total > 0 ? 'ok' : 'critico',
        obrigatorio: true,
        detalhe: `${administradores.rows[0].total} administrador(es) ativo(s).`
      },
      {
        titulo: 'Produtos cadastrados',
        status: produtos.rows[0].total > 0 ? 'ok' : 'critico',
        obrigatorio: true,
        detalhe: `${produtos.rows[0].total} produto(s) ativo(s).`
      },
      {
        titulo: 'NCM dos produtos',
        status: produtosSemNcm.rows[0].total === 0 ? 'ok' : 'critico',
        obrigatorio: true,
        detalhe: produtosSemNcm.rows[0].total === 0 ? 'Todos os produtos ativos têm NCM válido.' : `${produtosSemNcm.rows[0].total} produto(s) sem NCM válido.`
      },
      {
        titulo: 'Categorias',
        status: categorias.rows[0].total > 0 ? 'ok' : 'critico',
        obrigatorio: true,
        detalhe: `${categorias.rows[0].total} categoria(s) cadastrada(s).`
      },
      {
        titulo: 'Integração Bling',
        status: tokenValido ? 'ok' : 'critico',
        obrigatorio: true,
        detalhe: tokenValido ? 'Token conectado e dentro da validade.' : 'Conecte novamente com o Bling antes de emitir notas.'
      },
      {
        titulo: 'Backup automático',
        status: emailBackup ? 'ok' : 'aviso',
        obrigatorio: false,
        detalhe: emailBackup ? `Backup configurado para ${emailBackup}.` : 'Configure o e-mail de backup nas configurações.'
      },
      {
        titulo: 'Clientes identificados',
        status: clientesSemCpf.rows[0].total === 0 ? 'ok' : 'aviso',
        obrigatorio: false,
        detalhe: clientesSemCpf.rows[0].total === 0 ? 'Clientes PF ativos possuem CPF quando cadastrados.' : `${clientesSemCpf.rows[0].total} cliente(s) PF ativo(s) sem CPF.`
      },
      {
        titulo: 'Impressoras QZ',
        status: 'manual',
        obrigatorio: false,
        detalhe: 'Valide nos computadores da loja: romaneio, etiquetas, NF-e e NFC-e.'
      },
      {
        titulo: 'Sequência fiscal',
        status: 'manual',
        obrigatorio: true,
        detalhe: 'Antes de ir para produção, confirme no Bling a próxima numeração de NF-e/NFC-e.'
      },
      {
        titulo: 'Ambiente do Bling',
        status: 'manual',
        obrigatorio: true,
        detalhe: 'Confirme a troca de homologação para produção no momento certo.'
      }
    ];
    res.json({
      atualizadoEm: new Date().toISOString(),
      resumo: {
        ok: itens.filter(i => i.status === 'ok').length,
        avisos: itens.filter(i => i.status === 'aviso').length,
        criticos: itens.filter(i => i.status === 'critico').length,
        manuais: itens.filter(i => i.status === 'manual').length,
        bloqueadores: itens.filter(i => i.obrigatorio && i.status === 'critico').length
      },
      itens
    });
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
    caixaMovimentos, metasComissao, orcamentos, orcamentoItens
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
    pool.query('SELECT * FROM metas_comissao'),
    pool.query('SELECT * FROM orcamentos'),
    pool.query('SELECT * FROM orcamento_itens')
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
    metasComissao: metasComissao.rows,
    orcamentos: orcamentos.rows,
    orcamentoItens: orcamentoItens.rows
  };
}

// BACKUP — Exportação manual
app.get('/api/backup/exportar', auth, requireAdmin, async (req, res) => {
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
app.post('/api/backup/descriptografar', auth, requireAdmin, async (req, res) => {
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
app.post('/api/backup/enviar-email', auth, requireAdmin, async (req, res) => {
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
      vendas: backup.vendas.length,
      orcamentos: backup.orcamentos.length
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
          <li>${stats.orcamentos} orçamentos</li>
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
            <li>${backup.orcamentos.length} orçamentos</li>
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
    const { data, vendedor_id } = req.query;
    if (!data) return res.status(400).json({ erro: 'Informe a data' });

    const vendFiltro = vendedor_id ? ` AND v.vendedor_id = '${vendedor_id.replace(/'/g,"''")}'` : '';

    // Vendas do dia (exceto canceladas)
    const vendas = await pool.query(
      `SELECT v.*,
        f.nome as vendedor_nome_join
       FROM vendas v
       LEFT JOIN funcionarios f ON f.id = v.vendedor_id
       WHERE DATE(v.data AT TIME ZONE 'America/Sao_Paulo') = $1
         AND v.status != 'cancelada'
         AND (v.tipo IS NULL OR v.tipo NOT IN ('vale_funcionaria'))${vendFiltro}`,
      [data]
    );

    // Itens vendidos do dia
    const itens = await pool.query(
      `SELECT vi.*, p.custo, p.nome as produto_nome
       FROM venda_itens vi
       JOIN vendas v ON v.id = vi.venda_id
       LEFT JOIN produtos p ON p.id = vi.produto_id
       WHERE DATE(v.data AT TIME ZONE 'America/Sao_Paulo') = $1
         AND v.status != 'cancelada'
         AND (v.tipo IS NULL OR v.tipo NOT IN ('vale_funcionaria'))${vendFiltro}`,
      [data]
    );

    // Pagamentos do dia
    const pagamentos = await pool.query(
      `SELECT vp.*
       FROM venda_pagamentos vp
       JOIN vendas v ON v.id = vp.venda_id
       WHERE DATE(v.data AT TIME ZONE 'America/Sao_Paulo') = $1
         AND v.status != 'cancelada'
         AND (v.tipo IS NULL OR v.tipo NOT IN ('vale_funcionaria'))${vendFiltro}`,
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

// ATENDIMENTOS ABERTOS DO PDV
app.get('/api/pdv/atendimentos', auth, async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT id,nome,usuario_id,usuario_nome,cliente_id,cliente_nome,vendedor_id,vendedor_nome,total,qtd_pecas,estado,status,criado_em,atualizado_em
       FROM atendimentos_pdv
       WHERE status='aberto'
       ORDER BY criado_em ASC, id ASC
       LIMIT 100`
    );
    res.json(r.rows);
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.put('/api/pdv/atendimentos/:id', auth, async (req, res) => {
  try {
    const estado = req.body?.estado || {};
    const clienteId = estado.clienteId || null;
    const clienteNome = estado.clienteBusca || 'Consumidor final';
    const vendedorId = estado.vendedorId || null;
    const vendedor = vendedorId
      ? await pool.query('SELECT nome FROM funcionarios WHERE id=$1', [vendedorId]).then(r => r.rows[0]?.nome || '')
      : '';
    const qtdPecas = [...(estado.carrinho || []), ...(estado.carrinhoTroca || [])]
      .reduce((acc, item) => acc + (parseInt(item.qty, 10) || 0), 0);
    const totalCompras = (estado.carrinho || []).reduce((acc, item) => acc + (Number(item.preco) || 0) * (Number(item.qty) || 0), 0);
    const descontoTabela = totalCompras * ((Number(estado.descPct) || 0) / 100);
    const total = Math.max(0, totalCompras - descontoTabela - (Number(estado.descontoManual) || 0));
    await pool.query(
      `INSERT INTO atendimentos_pdv
       (id,nome,usuario_id,usuario_nome,cliente_id,cliente_nome,vendedor_id,vendedor_nome,total,qtd_pecas,estado,status,atualizado_em)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'aberto',NOW())
       ON CONFLICT (id) DO UPDATE SET
         nome=EXCLUDED.nome,
         usuario_id=EXCLUDED.usuario_id,
         usuario_nome=EXCLUDED.usuario_nome,
         cliente_id=EXCLUDED.cliente_id,
         cliente_nome=EXCLUDED.cliente_nome,
         vendedor_id=EXCLUDED.vendedor_id,
         vendedor_nome=EXCLUDED.vendedor_nome,
         total=EXCLUDED.total,
         qtd_pecas=EXCLUDED.qtd_pecas,
         estado=EXCLUDED.estado,
         status='aberto',
         atualizado_em=NOW()`,
      [
        req.params.id,
        estado.nome || req.body?.nome || 'Tela PDV',
        req.user.id,
        req.user.nome,
        clienteId,
        clienteNome,
        vendedorId,
        vendedor,
        total,
        qtdPecas,
        JSON.stringify(estado)
      ]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.delete('/api/pdv/atendimentos/:id', auth, async (req, res) => {
  try {
    await pool.query(
      `UPDATE atendimentos_pdv
       SET status='descartado', atualizado_em=NOW()
       WHERE id=$1`,
      [req.params.id]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// ORÇAMENTOS
app.get('/api/orcamentos', auth, async (req, res) => {
  try {
    const { status, q, limit, offset } = req.query;
    let where = ['1=1'];
    let params = [];
    let i = 1;
    if (status) { where.push(`o.status = $${i++}`); params.push(status); }
    if (q) {
      where.push(`(LOWER(o.num) LIKE $${i} OR LOWER(o.cliente_nome) LIKE $${i} OR LOWER(o.cliente_tel) LIKE $${i})`);
      params.push('%' + String(q).toLowerCase() + '%');
      i++;
    }
    const sql = `
      SELECT o.*,
        COALESCE(json_agg(jsonb_build_object('id',oi.produto_id,'nome',oi.nome,'cod',oi.cod,'preco',oi.preco,'qty',oi.qty,'tipo',COALESCE(oi.tipo,'novo')) ORDER BY oi.id) FILTER (WHERE oi.id IS NOT NULL),'[]') as itens
      FROM orcamentos o
      LEFT JOIN orcamento_itens oi ON oi.orcamento_id = o.id
      WHERE ${where.join(' AND ')}
      GROUP BY o.id
      ORDER BY o.data DESC
      LIMIT ${parseInt(limit) || 200} OFFSET ${parseInt(offset) || 0}`;
    const r = await pool.query(sql, params);
    res.json(r.rows);
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.post('/api/orcamentos', auth, async (req, res) => {
  const client = await pool.connect();
  try {
    const o = req.body || {};
    if (!Array.isArray(o.itens) || !o.itens.length) {
      return res.status(400).json({ erro: 'Informe ao menos uma peça para salvar o orçamento.' });
    }
    await client.query('BEGIN');
    const orcamentoId = o.id || uid();
    let num = o.num;
    if (!num) {
      const nums = await client.query(`SELECT num FROM orcamentos WHERE num ~ '^ORC-[0-9]+$'`);
      const prox = nums.rows.reduce((maior, row) => {
        const n = parseInt(String(row.num || '').replace(/\D/g, ''), 10) || 0;
        return Math.max(maior, n);
      }, 0) + 1;
      num = 'ORC-' + String(prox).padStart(4, '0');
    }
    await client.query(
      `INSERT INTO orcamentos
       (id,num,data,validade,cliente_id,cliente_nome,cliente_tel,vendedor_id,vendedor_nome,canal,subtotal,desconto,desc_pct,total,obs,status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
      [
        orcamentoId, num, o.data || new Date(), o.validade || null,
        o.clienteId || o.cliente_id || null,
        o.clienteNome || o.cliente_nome || 'Consumidor final',
        o.clienteTel || o.cliente_tel || '',
        o.vendedorId || o.vendedor_id || null,
        o.vendedorNome || o.vendedor_nome || '',
        o.canal || 'presencial',
        o.sub || o.subtotal || 0,
        o.desc || o.desconto || 0,
        o.descPct || o.desc_pct || 0,
        o.total || o.tot || 0,
        o.obs || '',
        o.status || 'aberto'
      ]
    );
    for (const item of o.itens) {
      await client.query(
        `INSERT INTO orcamento_itens (orcamento_id,produto_id,nome,cod,preco,qty,tipo)
         VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [orcamentoId, item.id || item.produto_id, item.nome, item.cod, item.preco, item.qty, item.tipo || 'novo']
      );
    }
    await client.query('COMMIT');
    res.json({ ok: true, num });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ erro: err.message });
  } finally { client.release(); }
});

app.patch('/api/orcamentos/:id/status', auth, async (req, res) => {
  try {
    const status = req.body?.status || 'cancelado';
    await pool.query(
      `UPDATE orcamentos SET status=$1, atualizado_em=NOW() WHERE id=$2`,
      [status, req.params.id]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

app.patch('/api/orcamentos/:id/converter', auth, async (req, res) => {
  try {
    await pool.query(
      `UPDATE orcamentos
       SET status='convertido', convertido_venda_id=$1, convertido_em=NOW(), atualizado_em=NOW()
       WHERE id=$2`,
      [req.body?.vendaId || null, req.params.id]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// ─── BLING NF-e / NFC-e ──────────────────────────────────────────────────────
function calcularCFOP(ufCliente, tipoPessoa, ie) {
  if (!ufCliente || ufCliente.toUpperCase() === 'RJ') return '5102';
  const isContribuinte = tipoPessoa === 'PJ' && ie && ie.trim() !== '' && ie.toUpperCase() !== 'ISENTO';
  if (isContribuinte) return '6102';
  return '6108';
}

function coletarMensagensBling(obj, acc = []) {
  if (!obj) return acc;
  if (typeof obj === 'string') {
    const texto = obj.trim();
    if (texto) acc.push(texto);
    return acc;
  }
  if (Array.isArray(obj)) {
    obj.forEach(item => coletarMensagensBling(item, acc));
    return acc;
  }
  if (typeof obj === 'object') {
    ['message', 'mensagem', 'description', 'descricao', 'detail', 'detalhe'].forEach(chave => {
      if (typeof obj[chave] === 'string' && obj[chave].trim()) acc.push(obj[chave].trim());
    });
    Object.values(obj).forEach(valor => coletarMensagensBling(valor, acc));
  }
  return acc;
}

function resumirErroBling(data, fallback) {
  const mensagens = [...new Set(coletarMensagensBling(data).filter(Boolean))];
  if (!mensagens.length) return fallback;
  return mensagens.join(' | ');
}

function coletarMotivosBling(obj, acc = []) {
  if (!obj) return acc;
  if (Array.isArray(obj)) {
    obj.forEach(item => coletarMotivosBling(item, acc));
    return acc;
  }
  if (typeof obj !== 'object') return acc;

  ['message', 'mensagem', 'description', 'descricao', 'detail', 'detalhe', 'error', 'erro', 'reason', 'motivo'].forEach(chave => {
    if (typeof obj[chave] === 'string' && obj[chave].trim()) acc.push(obj[chave].trim());
  });

  Object.values(obj).forEach(valor => {
    if (valor && typeof valor === 'object') coletarMotivosBling(valor, acc);
  });
  return acc;
}

function extrairMotivoBling(data, fallback = '') {
  const mensagens = [...new Set(coletarMotivosBling(data).filter(Boolean))];
  if (!mensagens.length) return fallback;
  const candidatasFortes = mensagens.filter(msg => {
    const normalizada = normalizarTextoBling(msg);
    return (
      normalizada.includes('rejei') ||
      normalizada.includes('erro') ||
      normalizada.includes('deneg') ||
      normalizada.includes('duplicidade') ||
      normalizada.includes('sefaz') ||
      normalizada.includes('schema') ||
      normalizada.includes('chave') ||
      normalizada.includes('campo') ||
      normalizada.includes('cnpj') ||
      normalizada.includes('cpf') ||
      normalizada.includes('ie') ||
      normalizada.includes('inscr') ||
      /\b\d{3}\b/.test(normalizada)
    );
  });
  return candidatasFortes[0] || mensagens[0] || fallback;
}

function esperar(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

let ultimoRequestBlingEm = 0;

async function requisicaoBling(caminho, token, options = {}) {
  const tentativas = options.tentativas || 3;
  const method = options.method || 'GET';
  const body = options.body;

  for (let tentativa = 1; tentativa <= tentativas; tentativa++) {
    const agora = Date.now();
    const intervaloMinimo = 380;
    const esperaAntes = Math.max(0, intervaloMinimo - (agora - ultimoRequestBlingEm));
    if (esperaAntes > 0) await esperar(esperaAntes);

    const response = await fetch(`https://api.bling.com.br/Api/v3/${caminho}`, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      ...(body !== undefined ? { body: typeof body === 'string' ? body : JSON.stringify(body) } : {})
    });
    ultimoRequestBlingEm = Date.now();

    const texto = await response.text();
    let data = null;
    try { data = texto ? JSON.parse(texto) : null; } catch (_) {}

    if (response.status !== 429 || tentativa === tentativas) {
      return { status: response.status, data, texto };
    }

    const retryAfter = Number(response.headers.get('retry-after'));
    const espera = Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : tentativa * 600;
    console.warn(`Bling rate limit em ${caminho}; aguardando ${espera}ms antes da tentativa ${tentativa + 1}.`);
    await esperar(espera);
  }
}

async function consultarBlingPorId(caminho, token) {
  return requisicaoBling(caminho, token);
}

function decodificarXml(texto = '') {
  return String(texto)
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
}

function obterBlocoXml(xml = '', tag) {
  const match = String(xml).match(new RegExp(`<(?:[\\w.-]+:)?${tag}\\b[^>]*>([\\s\\S]*?)<\\/(?:[\\w.-]+:)?${tag}>`, 'i'));
  return match ? match[1] : '';
}

function obterValorXml(xml = '', tag) {
  const match = String(xml).match(new RegExp(`<(?:[\\w.-]+:)?${tag}\\b[^>]*>([\\s\\S]*?)<\\/(?:[\\w.-]+:)?${tag}>`, 'i'));
  return match ? decodificarXml(match[1].trim()) : '';
}

function limparDocumentoFiscal(valor = '') {
  return String(valor || '').replace(/\D/g, '');
}

function normalizarNomeCampoFiscal(campo = '') {
  return String(campo || '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-zA-Z0-9]/g, '')
    .toLowerCase();
}

function buscarValorFiscalProfundo(obj, nomes = [], filtro = () => true) {
  const nomesNormalizados = new Set(nomes.map(normalizarNomeCampoFiscal));
  const visitados = new Set();

  function visitar(valor) {
    if (!valor || typeof valor !== 'object') return '';
    if (visitados.has(valor)) return '';
    visitados.add(valor);

    if (Array.isArray(valor)) {
      for (const item of valor) {
        const achado = visitar(item);
        if (achado) return achado;
      }
      return '';
    }

    for (const [chave, conteudo] of Object.entries(valor)) {
      if (nomesNormalizados.has(normalizarNomeCampoFiscal(chave)) && filtro(conteudo)) {
        return conteudo;
      }
    }

    for (const conteudo of Object.values(valor)) {
      const achado = visitar(conteudo);
      if (achado) return achado;
    }

    return '';
  }

  return visitar(obj);
}

function buscarDocumentoFiscalProfundo(obj, nomes = [], tamanho = null) {
  const valor = buscarValorFiscalProfundo(obj, nomes, conteudo => {
    const doc = limparDocumentoFiscal(conteudo);
    return tamanho ? doc.length === tamanho : !!doc;
  });
  return limparDocumentoFiscal(valor);
}

function formatarDataHoraFiscal(valor = '') {
  if (!valor) return '';
  const data = new Date(valor);
  if (Number.isNaN(data.getTime())) return valor;
  return data.toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' });
}

function extrairEnderecoFiscal(bloco = '') {
  return {
    logradouro: obterValorXml(bloco, 'xLgr'),
    numero: obterValorXml(bloco, 'nro'),
    complemento: obterValorXml(bloco, 'xCpl'),
    bairro: obterValorXml(bloco, 'xBairro'),
    municipio: obterValorXml(bloco, 'xMun'),
    uf: obterValorXml(bloco, 'UF'),
    cep: obterValorXml(bloco, 'CEP')
  };
}

function extrairDanfeSimplificadoDoXml(xml = {}, nota = {}) {
  const textoXml = String(xml || '');
  const infNFe = obterBlocoXml(textoXml, 'infNFe') || textoXml;
  const ide = obterBlocoXml(infNFe, 'ide');
  const emit = obterBlocoXml(infNFe, 'emit');
  const dest = obterBlocoXml(infNFe, 'dest');
  const infProt = obterBlocoXml(textoXml, 'infProt');
  const total = obterBlocoXml(obterBlocoXml(infNFe, 'total'), 'ICMSTot');
  const chaveDoId = (String(textoXml.match(/<(?:[\w.-]+:)?infNFe\b[^>]*\bId=["']NFe(\d{44})["']/i)?.[1] || '').replace(/\D/g, ''));
  const chaveNota = buscarDocumentoFiscalProfundo(nota, [
    'chaveAcesso', 'chaveAcessoNFe', 'chaveAcessoNfe', 'chaveNFe', 'chaveNfe', 'chave'
  ], 44);
  const protocoloNota = buscarValorFiscalProfundo(nota, [
    'protocolo', 'numeroProtocolo', 'protocoloAutorizacao', 'nProt', 'numeroProtocoloAutorizacao'
  ], conteudo => !!String(conteudo || '').trim());
  const dataAutorizacaoNota = buscarValorFiscalProfundo(nota, [
    'dataAutorizacao', 'dataHoraAutorizacao', 'dhRecbto', 'dataProtocolo', 'dataEmissao'
  ], conteudo => !!String(conteudo || '').trim());
  const situacaoNota = buscarValorFiscalProfundo(nota, [
    'situacao', 'status', 'descricaoSituacao', 'situacaoNota'
  ], conteudo => typeof conteudo !== 'object' && !!String(conteudo || '').trim());

  const itens = [...textoXml.matchAll(/<det\b[^>]*>([\s\S]*?)<\/det>/gi)]
    .map(match => {
      const prod = obterBlocoXml(match[1], 'prod');
      return {
        codigo: obterValorXml(prod, 'cProd'),
        descricao: obterValorXml(prod, 'xProd'),
        quantidade: obterValorXml(prod, 'qCom'),
        valorUnitario: obterValorXml(prod, 'vUnCom'),
        valorTotal: obterValorXml(prod, 'vProd')
      };
    })
    .filter(item => item.descricao || item.codigo);

  return {
    chaveAcesso: limparDocumentoFiscal(obterValorXml(infProt, 'chNFe') || chaveDoId || chaveNota),
    protocolo: obterValorXml(infProt, 'nProt') || protocoloNota || '',
    dataAutorizacao: formatarDataHoraFiscal(obterValorXml(infProt, 'dhRecbto') || dataAutorizacaoNota || ''),
    situacao: situacaoNota || '',
    ambiente: obterValorXml(ide, 'tpAmb') || '',
    modelo: obterValorXml(ide, 'mod') || '55',
    tipoOperacao: obterValorXml(ide, 'tpNF') === '0' ? 'Entrada' : 'Saída',
    serie: obterValorXml(ide, 'serie') || nota.serie || '',
    numero: obterValorXml(ide, 'nNF') || nota.numero || '',
    dataEmissao: formatarDataHoraFiscal(obterValorXml(ide, 'dhEmi') || obterValorXml(ide, 'dEmi') || nota.dataOperacao || nota.dataEmissao || ''),
    naturezaOperacao: obterValorXml(ide, 'natOp') || '',
    valorTotal: obterValorXml(total, 'vNF') || nota.valorNota || nota.total || '',
    emitente: {
      nome: obterValorXml(emit, 'xNome'),
      fantasia: obterValorXml(emit, 'xFant'),
      cnpj: obterValorXml(emit, 'CNPJ'),
      ie: obterValorXml(emit, 'IE'),
      endereco: extrairEnderecoFiscal(obterBlocoXml(emit, 'enderEmit'))
    },
    destinatario: {
      nome: obterValorXml(dest, 'xNome') || nota.contato?.nome || '',
      documento: obterValorXml(dest, 'CNPJ') || obterValorXml(dest, 'CPF') || nota.contato?.numeroDocumento || '',
      ie: obterValorXml(dest, 'IE') || '',
      endereco: extrairEnderecoFiscal(obterBlocoXml(dest, 'enderDest'))
    },
    itens: itens.slice(0, 8)
  };
}

async function carregarXmlNotaBling(nota = {}, token) {
  const fonteXmlBruta = nota.xml || nota.linkXML || nota.linkXml || nota.linkXmlNfe || nota.linkXMLNfe || nota.linkXmlNotaFiscal;
  const fonteXml = typeof fonteXmlBruta === 'object' && fonteXmlBruta !== null
    ? (fonteXmlBruta.url || fonteXmlBruta.link || fonteXmlBruta.href || fonteXmlBruta.download)
    : fonteXmlBruta;
  if (!fonteXml) return '';

  const textoFonte = String(fonteXml).trim();
  if (textoFonte.trim().startsWith('<')) return textoFonte;
  const urlXml = textoFonte.startsWith('//')
    ? 'https:' + textoFonte
    : textoFonte.startsWith('/')
      ? 'https://www.bling.com.br' + textoFonte
      : textoFonte;

  try {
    const response = await fetch(urlXml, {
      headers: {
        Accept: 'application/xml,text/xml,*/*',
        Authorization: 'Bearer ' + token
      }
    });
    if (!response.ok) return '';
    return response.text();
  } catch (err) {
    console.warn('Não foi possível carregar XML da NF-e pelo link do Bling:', err.message);
    return '';
  }
}

async function obterProximoNumeroFiscalBling(tipoNota, token) {
  const consulta = await consultarBlingPorId(`${tipoNota}?limite=100`, token);
  const notas = Array.isArray(consulta?.data?.data) ? consulta.data.data : [];
  if (consulta.status < 200 || consulta.status >= 300 || !notas.length) return null;

  const maiorNumero = notas.reduce((maior, nota) => {
    const numero = parseInt(String(nota.numero || '').replace(/\D/g, ''), 10);
    return Number.isFinite(numero) && numero > maior ? numero : maior;
  }, 0);

  if (!maiorNumero) return null;
  return String(maiorNumero + 1).padStart(6, '0');
}

function normalizarTextoBling(texto) {
  return String(texto || '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .trim();
}

const BLING_STATUS_NFE_MAP = {
  '1': 'pendente',
  '2': 'cancelada',
  '3': 'aguardando recibo',
  '4': 'rejeitada',
  '5': 'autorizada',
  '6': 'emitida danfe',
  '7': 'registrada',
  '8': 'aguardando protocolo',
  '9': 'denegada',
  '10': 'consulta situacao',
  '11': 'bloqueada'
};

function normalizarSituacaoNotaFiscalBling(valor = '') {
  const texto = String(valor || '').trim();
  if (!texto) return '';
  return BLING_STATUS_NFE_MAP[texto] || texto;
}

function converterValorBlingNumero(valor) {
  if (typeof valor === 'number') return Number.isFinite(valor) ? valor : 0;
  const texto = String(valor || '').trim();
  if (!texto) return 0;
  const normalizado = texto.includes(',')
    ? texto.replace(/\./g, '').replace(',', '.')
    : texto;
  const numero = parseFloat(normalizado);
  return Number.isFinite(numero) ? numero : 0;
}

function extrairNomeNotaFiscalBling(nota = {}) {
  const candidatos = [
    nota.nome,
    nota.contato?.nome,
    nota.cliente?.nome,
    nota.destinatario?.nome
  ];
  for (const candidato of candidatos) {
    if (candidato !== undefined && candidato !== null && String(candidato).trim()) return String(candidato).trim();
  }
  return '';
}

function extrairValorNotaFiscalBling(nota = {}) {
  const candidatos = [
    nota.valor,
    nota.valorNota,
    nota.total,
    nota.valorTotal
  ];
  for (const candidato of candidatos) {
    const numero = converterValorBlingNumero(candidato);
    if (numero > 0) return numero;
  }
  return 0;
}

function extrairDataNotaFiscalBling(nota = {}) {
  const candidatos = [
    nota.dataEmissao,
    nota.data,
    nota.dataOperacao
  ];
  for (const candidato of candidatos) {
    if (!candidato) continue;
    const data = new Date(candidato);
    if (!Number.isNaN(data.getTime())) return data.toISOString().slice(0, 10);
    const texto = String(candidato).trim();
    if (/^\d{4}-\d{2}-\d{2}/.test(texto)) return texto.slice(0, 10);
    if (/^\d{2}\/\d{2}\/\d{4}$/.test(texto)) {
      const [dia, mes, ano] = texto.split('/');
      return `${ano}-${mes}-${dia}`;
    }
  }
  return '';
}

function chaveCorrespondenciaNotaFiscal({ nome = '', valor = 0, data = '' } = {}) {
  const nomeNormalizado = normalizarTextoBling(nome).replace(/\s+/g, ' ').trim();
  const totalCentavos = Math.round(converterValorBlingNumero(valor) * 100);
  const dataNormalizada = String(data || '').trim().slice(0, 10);
  if (!nomeNormalizado || !totalCentavos || !dataNormalizada) return '';
  return `${nomeNormalizado}__${totalCentavos}__${dataNormalizada}`;
}

function extrairSituacaoNotaFiscal(nota = {}) {
  const candidatos = [
    nota.status,
    nota.situacao,
    nota.descricaoSituacao,
    nota.situacaoNota,
    nota.statusNota
  ];

  for (const candidato of candidatos) {
    if (!candidato) continue;
    if (typeof candidato === 'object') {
      const valor = candidato.descricao || candidato.nome || candidato.valor || candidato.label || candidato.codigo || candidato.id;
      if (valor !== undefined && valor !== null && String(valor).trim()) return normalizarSituacaoNotaFiscalBling(String(valor).trim());
      continue;
    }
    if (String(candidato).trim()) return normalizarSituacaoNotaFiscalBling(String(candidato).trim());
  }

  return '';
}

async function listarNotasFiscaisRecentesBling(token, tipoNota = 'nfe') {
  const consulta = await consultarBlingPorId(`${tipoNota}?limite=100`, token);
  if (consulta.status < 200 || consulta.status >= 300) return [];
  return Array.isArray(consulta.data?.data) ? consulta.data.data : [];
}

function encontrarNotaNaListagemBling(notas = [], { id = '', numero = '' } = {}) {
  const idAlvo = String(id || '').trim();
  const numeroAlvo = String(numero || '').trim().replace(/\D/g, '');
  return notas.find(nota => {
    const idNota = String(nota?.id || '').trim();
    const numeroNota = String(nota?.numero || '').trim().replace(/\D/g, '');
    return (idAlvo && idNota === idAlvo) || (numeroAlvo && numeroNota === numeroAlvo);
  }) || null;
}

async function enriquecerSituacaoNotaFiscalBling(nota = {}, token, cache = null, tipoNota = 'nfe') {
  if (!nota || typeof nota !== 'object') return nota;
  const situacaoAtual = extrairSituacaoNotaFiscal(nota);
  const situacaoNormalizada = normalizarTextoBling(situacaoAtual);
  const precisaSincronizar = !situacaoNormalizada
    || situacaoNormalizada === 'pendente'
    || situacaoNormalizada === 'aguardando recibo'
    || situacaoNormalizada === 'aguardando protocolo'
    || situacaoNormalizada === 'consulta situacao';

  if (!precisaSincronizar) return nota;

  if (!cache) cache = {};
  const chaveCache = `notasRecentes_${tipoNota}`;
  if (!cache[chaveCache]) {
    cache[chaveCache] = await listarNotasFiscaisRecentesBling(token, tipoNota).catch(err => {
      console.warn(`Falha ao listar ${tipoNota.toUpperCase()}s recentes no Bling:`, err.message);
      return [];
    });
  }

  const notaDaLista = encontrarNotaNaListagemBling(cache[chaveCache], {
    id: nota.id,
    numero: nota.numero
  });

  if (!notaDaLista) return nota;

  const situacaoLista = extrairSituacaoNotaFiscal(notaDaLista);
  if (!situacaoLista) return nota;

  return {
    ...nota,
    status: situacaoLista,
    situacaoBlingLista: situacaoLista
  };
}

function ordenarVendaParaCorrespondencia(a, b) {
  const dataA = new Date(a?.data || 0).getTime();
  const dataB = new Date(b?.data || 0).getTime();
  if (dataB !== dataA) return dataB - dataA;
  return String(b?.num || '').localeCompare(String(a?.num || ''), 'pt-BR', { numeric: true });
}

function ordenarNotaBlingParaCorrespondencia(a, b) {
  const numeroA = parseInt(String(a?.numero || '').replace(/\D/g, ''), 10) || 0;
  const numeroB = parseInt(String(b?.numero || '').replace(/\D/g, ''), 10) || 0;
  if (numeroB !== numeroA) return numeroB - numeroA;
  const dataA = new Date(a?.dataEmissao || a?.data || 0).getTime();
  const dataB = new Date(b?.dataEmissao || b?.data || 0).getTime();
  return dataB - dataA;
}

async function aplicarSituacaoNotaBlingNaVenda(venda, notaDaLista) {
  if (!venda || !notaDaLista) return;
  const situacaoLista = extrairSituacaoNotaFiscal(notaDaLista);
  if (!situacaoLista) return;
  const numeroLista = notaDaLista.numero ? String(notaDaLista.numero) : '';
  if (situacaoLista === venda.nfe_situacao && (!!numeroLista ? numeroLista === String(venda.nfe_numero || '') : true)) return;
  venda.nfe_situacao = situacaoLista;
  if (numeroLista) venda.nfe_numero = numeroLista;
  if (notaDaLista.id) venda.nfe_id = String(notaDaLista.id);
  await pool.query(
    `UPDATE vendas
     SET nfe_situacao=$1,
         nfe_numero=COALESCE(NULLIF($2,''), nfe_numero),
         nfe_id=COALESCE(NULLIF($3,''), nfe_id)
     WHERE id=$4`,
    [situacaoLista, numeroLista, notaDaLista.id ? String(notaDaLista.id) : '', venda.id]
  );
}

async function sincronizarSituacaoNFeDasVendas(vendas = []) {
  const candidatas = vendas.filter(venda => {
    if (!venda?.nfe_id) return false;
    const situacao = normalizarTextoBling(venda.nfe_situacao || '');
    return !situacao
      || situacao === 'pendente'
      || situacao === 'aguardando recibo'
      || situacao === 'aguardando protocolo'
      || situacao === 'consulta situacao';
  });

  if (!candidatas.length) return vendas;

  try {
    const token = await getBlingToken();
    const notasRecentes = await listarNotasFiscaisRecentesBling(token);
    if (!notasRecentes.length) return vendas;
    const notasUsadas = new Set();
    const vendasSemMatchDireto = [];

    for (const venda of candidatas) {
      const notaDaLista = encontrarNotaNaListagemBling(notasRecentes, {
        id: venda.nfe_id,
        numero: venda.nfe_numero
      });
      if (notaDaLista) {
        notasUsadas.add(String(notaDaLista.id || notaDaLista.numero || ''));
        await aplicarSituacaoNotaBlingNaVenda(venda, notaDaLista);
        continue;
      }
      vendasSemMatchDireto.push(venda);
    }

    const notasDisponiveis = notasRecentes.filter(nota => {
      const chave = String(nota?.id || nota?.numero || '');
      return chave && !notasUsadas.has(chave);
    });

    const vendasPorChave = new Map();
    for (const venda of vendasSemMatchDireto) {
      const chave = chaveCorrespondenciaNotaFiscal({
        nome: venda.cliente_nome,
        valor: venda.tot,
        data: venda.data ? new Date(venda.data).toISOString().slice(0, 10) : ''
      });
      if (!chave) continue;
      if (!vendasPorChave.has(chave)) vendasPorChave.set(chave, []);
      vendasPorChave.get(chave).push(venda);
    }

    const notasPorChave = new Map();
    for (const nota of notasDisponiveis) {
      const chave = chaveCorrespondenciaNotaFiscal({
        nome: extrairNomeNotaFiscalBling(nota),
        valor: extrairValorNotaFiscalBling(nota),
        data: extrairDataNotaFiscalBling(nota)
      });
      if (!chave) continue;
      if (!notasPorChave.has(chave)) notasPorChave.set(chave, []);
      notasPorChave.get(chave).push(nota);
    }

    for (const [chave, vendasGrupo] of vendasPorChave.entries()) {
      const notasGrupo = notasPorChave.get(chave);
      if (!notasGrupo?.length) continue;
      const vendasOrdenadas = [...vendasGrupo].sort(ordenarVendaParaCorrespondencia);
      const notasOrdenadas = [...notasGrupo].sort(ordenarNotaBlingParaCorrespondencia);
      const limite = Math.min(vendasOrdenadas.length, notasOrdenadas.length);
      for (let i = 0; i < limite; i++) {
        await aplicarSituacaoNotaBlingNaVenda(vendasOrdenadas[i], notasOrdenadas[i]);
      }
    }
  } catch (err) {
    console.error('Falha ao sincronizar situações de NF-e no histórico:', err);
  }

  return vendas;
}

function valorParaCentavos(valor) {
  const numero = parseFloat(valor) || 0;
  return Math.round(numero * 100);
}

function centavosParaValor(centavos) {
  return Math.round(centavos) / 100;
}

async function listarFormasPagamentoBling(token) {
  const caminhos = [
    'formas-pagamentos?limite=100',
    'formas-pagamento?limite=100',
    'formas_pagamentos?limite=100',
    'formasPagamento?limite=100'
  ];

  for (const caminho of caminhos) {
    try {
      const consulta = await consultarBlingPorId(caminho, token);
      const lista = Array.isArray(consulta?.data?.data) ? consulta.data.data : null;
      if (consulta.status >= 200 && consulta.status < 300 && lista) {
        return lista;
      }
    } catch (err) {
      console.warn('Falha ao consultar formas de pagamento no Bling:', caminho, err.message);
    }
  }

  return [];
}

function mapearFormaPagamentoBling(tipoPagamento, formasBling) {
  const aliases = {
    dinheiro: ['dinheiro', 'a vista', 'avista', 'cash'],
    debito: ['debito', 'cartao debito', 'cartao de debito'],
    credito: ['credito', 'cartao credito', 'cartao de credito'],
    pix: ['pix'],
    cheque: ['cheque'],
    cheque_pre: ['cheque pre', 'pre datado', 'pre-datado'],
    vale_funcionaria: ['vale', 'outros']
  };

  const procurados = aliases[tipoPagamento] || [tipoPagamento];
  const listaNormalizada = (formasBling || []).map(item => {
    const descricao = item.descricao || item.nome || item.rotulo || '';
    return { ...item, descricaoNormalizada: normalizarTextoBling(descricao) };
  });

  for (const alias of procurados) {
    const alvo = normalizarTextoBling(alias);
    const matchExato = listaNormalizada.find(item => item.descricaoNormalizada === alvo);
    if (matchExato?.id) return Number(matchExato.id);
    const matchParcial = listaNormalizada.find(item => item.descricaoNormalizada.includes(alvo));
    if (matchParcial?.id) return Number(matchParcial.id);
  }

  return null;
}

app.get('/api/bling/nfe/:id', auth, async (req, res) => {
  try {
    const token = await getBlingToken();
    const consulta = await consultarBlingPorId(`nfe/${req.params.id}`, token);
    if (consulta.status < 200 || consulta.status >= 300) {
      return res.status(400).json({
        erro: resumirErroBling(consulta.data, 'Erro ao consultar NF-e no Bling'),
        detalhes: consulta.data || consulta.texto
      });
    }
    const nota = await enriquecerSituacaoNotaFiscalBling(consulta.data?.data || {}, token);
    res.json({ ok: true, nfe: nota });
  } catch (err) {
    console.error('Erro ao consultar NF-e:', err);
    res.status(500).json({ erro: err.message });
  }
});

app.get('/api/bling/nfce/:id', auth, async (req, res) => {
  try {
    const token = await getBlingToken();
    const consulta = await consultarBlingPorId(`nfce/${req.params.id}`, token);
    if (consulta.status < 200 || consulta.status >= 300) {
      return res.status(400).json({
        erro: resumirErroBling(consulta.data, 'Erro ao consultar NFC-e no Bling'),
        detalhes: consulta.data || consulta.texto
      });
    }
    const nota = await enriquecerSituacaoNotaFiscalBling(consulta.data?.data || {}, token, null, 'nfce');
    res.json({ ok: true, nfce: nota });
  } catch (err) {
    console.error('Erro ao consultar NFC-e:', err);
    res.status(500).json({ erro: err.message });
  }
});

app.get('/api/bling/nfe/:id/pdf', auth, async (req, res) => {
  try {
    const token = await getBlingToken();
    const consulta = await consultarBlingPorId(`nfe/${req.params.id}`, token);
    if (consulta.status < 200 || consulta.status >= 300) {
      return res.status(400).json({
        erro: resumirErroBling(consulta.data, 'Erro ao consultar NF-e no Bling'),
        detalhes: consulta.data || consulta.texto
      });
    }

    const nota = consulta.data?.data || {};
    const linkPDF = nota.linkPDF || nota.linkDanfe;
    if (!linkPDF) {
      return res.status(404).json({ erro: 'Bling não retornou o PDF/DANFE da NF-e.' });
    }

    const pdfResponse = await fetch(linkPDF, {
      headers: {
        Accept: 'application/pdf,*/*',
        Authorization: 'Bearer ' + token
      }
    });

    if (!pdfResponse.ok) {
      const texto = await pdfResponse.text().catch(() => '');
      return res.status(400).json({
        erro: 'Não foi possível carregar o PDF da NF-e no Bling.',
        detalhes: texto.slice(0, 500)
      });
    }

    const buffer = Buffer.from(await pdfResponse.arrayBuffer());
    const contentType = pdfResponse.headers.get('content-type') || 'application/pdf';
    const numero = String(nota.numero || req.params.id).replace(/[^\w.-]/g, '') || req.params.id;

    res.set({
      'Content-Type': contentType.includes('pdf') ? contentType : 'application/pdf',
      'Content-Disposition': `inline; filename="nfe-${numero}.pdf"`,
      'Content-Length': buffer.length
    });
    res.send(buffer);
  } catch (err) {
    console.error('Erro ao carregar PDF da NF-e:', err);
    res.status(500).json({ erro: err.message });
  }
});

app.get('/api/bling/nfe/:id/danfe-simplificado', auth, async (req, res) => {
  try {
    const token = await getBlingToken();
    const consulta = await consultarBlingPorId(`nfe/${req.params.id}`, token);
    if (consulta.status < 200 || consulta.status >= 300) {
      return res.status(400).json({
        erro: resumirErroBling(consulta.data, 'Erro ao consultar NF-e no Bling'),
        detalhes: consulta.data || consulta.texto
      });
    }

    const nota = consulta.data?.data || {};
    const xml = await carregarXmlNotaBling(nota, token);
    const danfe = xml ? extrairDanfeSimplificadoDoXml(xml, nota) : extrairDanfeSimplificadoDoXml('', nota);

    if (!danfe.chaveAcesso || danfe.chaveAcesso.length !== 44) {
      return res.status(400).json({
        erro: 'Não consegui obter a chave de acesso da NF-e no Bling. Abra o DANFE completo do Bling para esta nota.',
        detalhes: { notaId: req.params.id, numero: nota.numero || '', temXml: !!xml }
      });
    }

    res.json({ ok: true, danfe });
  } catch (err) {
    console.error('Erro ao montar DANFE simplificado:', err);
    res.status(500).json({ erro: err.message });
  }
});

app.post('/api/bling/nfe', auth, async (req, res) => {
  try {
    const { vendaId } = req.body;

    const vendaRes = await pool.query(
      `SELECT v.*, c.nome as cli_nome, c.cpf, c.cnpj, c.ie, c.tipo as cli_tipo,
              e.logradouro, e.numero, e.bairro, e.cidade,
              COALESCE(NULLIF(e.uf, ''), NULLIF(e.estado, '')) as uf,
              e.cep
       FROM vendas v
       LEFT JOIN clientes c ON c.id = v.cliente_id
       LEFT JOIN enderecos_cliente e ON e.cliente_id = v.cliente_id AND e.principal = true
       WHERE v.id = $1`,
      [vendaId]
    );
    if (!vendaRes.rows.length) return res.status(404).json({ erro: 'Venda não encontrada' });
    const venda = vendaRes.rows[0];

    if (!venda.cliente_id) {
      return res.status(400).json({ erro: 'A NF-e exige um cliente vinculado à venda.' });
    }

    const faltandoEndereco = [];
    if (!venda.logradouro) faltandoEndereco.push('logradouro');
    if (!venda.bairro) faltandoEndereco.push('bairro');
    if (!venda.cidade) faltandoEndereco.push('cidade');
    if (!venda.uf) faltandoEndereco.push('UF');
    if (!venda.cep) faltandoEndereco.push('CEP');
    if (faltandoEndereco.length) {
      return res.status(400).json({ erro: 'Cliente sem endereço principal completo para NF-e: ' + faltandoEndereco.join(', ') + '.' });
    }

    if (venda.cli_tipo === 'PJ' && !(venda.cnpj || '').replace(/\D/g, '')) {
      return res.status(400).json({ erro: 'Cliente PJ sem CNPJ cadastrado.' });
    }

    const itensRes = await pool.query(
      `SELECT vi.*, p.ncm, p.csosn, p.custo
       FROM venda_itens vi
       LEFT JOIN produtos p ON p.id = vi.produto_id
       WHERE vi.venda_id = $1 AND vi.tipo != 'devolvido'`,
      [vendaId]
    );

    if (!itensRes.rows.length) {
      return res.status(400).json({ erro: 'Venda sem itens válidos para emitir NF-e.' });
    }

    const itensSemNCM = itensRes.rows
      .filter(item => !normalizarNCM(item.ncm))
      .map(item => item.nome || item.cod || 'item sem identificação');
    if (itensSemNCM.length) {
      return res.status(400).json({ erro: 'Os seguintes produtos estão sem NCM: ' + itensSemNCM.join(', ') + '.' });
    }

    const token = await getBlingToken();

    const dataOperacao = new Date(venda.data).toISOString().split('T')[0];
    const cfop = parseInt(calcularCFOP(venda.uf, venda.cli_tipo, venda.ie));

    const vProd = itensRes.rows.reduce((a, i) => a + parseFloat(i.preco) * parseInt(i.qty), 0);
    const vNF = parseFloat(venda.tot);
    const fatorDesc = vProd > 0 && vNF < vProd ? vNF / vProd : 1;

    const somaItensComDesc = itensRes.rows.reduce((a, i) => {
      return a + Math.round(parseFloat(i.preco) * fatorDesc * 100) / 100 * parseInt(i.qty);
    }, 0);
    const proximoNumeroNFe = await obterProximoNumeroFiscalBling('nfe', token);

    const payload = {
      tipo: 1,
      dataOperacao: dataOperacao,
      contato: {
        nome: venda.cli_nome || 'Consumidor Final',
        tipoPessoa: venda.cli_tipo === 'PJ' ? 'J' : 'F',
        numeroDocumento: (venda.cpf || venda.cnpj || '').replace(/\D/g, ''),
        ie: venda.cli_tipo === 'PJ' ? (venda.ie || 'ISENTO') : 'ISENTO',
        endereco: {
          endereco: venda.logradouro || '',
          numero: venda.numero || 'S/N',
          bairro: venda.bairro || '',
          municipio: venda.cidade || 'Petrópolis',
          uf: venda.uf || 'RJ',
          cep: (venda.cep || '').replace(/\D/g, '')
        }
      },
      itens: itensRes.rows.map(item => {
        const precoComDesc = Math.round(parseFloat(item.preco) * fatorDesc * 100) / 100;
        const ncm = normalizarNCM(item.ncm);
        return {
          codigo: item.cod || '',
          descricao: item.nome || '',
          ncm,
          classificacaoFiscal: ncm,
          unidade: 'PC',
          quantidade: parseFloat(item.qty),
          valor: precoComDesc,
          cfop,
          tipo: 'P',
          tributos: {
            icms: {
              cst: item.csosn || '102',
              modBC: 3,
              baseCalculoIcms: 0,
              aliquotaIcms: 0,
              valorIcms: 0
            }
          }
        };
      }),
      transporte: { fretePorConta: 9 },
      parcelas: [{
        dias: 0,
        data: dataOperacao,
        valor: Math.round(somaItensComDesc * 100) / 100
      }]
    };
    if (proximoNumeroNFe) payload.numero = proximoNumeroNFe;

    const criacao = await requisicaoBling('nfe', token, {
      method: 'POST',
      body: payload
    });

    if (criacao.status < 200 || criacao.status >= 300) {
      const erroDetalhado = resumirErroBling(criacao.data, 'Erro ao emitir NF-e');
      return res.status(400).json({
        erro: erroDetalhado,
        detalhes: criacao.data || criacao.texto
      });
    }

    const nfeId = criacao.data?.data?.id;
    if (!nfeId) {
      return res.status(400).json({
        erro: 'Bling não retornou o ID da NF-e criada.',
        detalhes: criacao.data || criacao.texto
      });
    }

    await pool.query(
      'UPDATE vendas SET nfe_id=$1, nfe_numero=$2, nfe_situacao=$3 WHERE id=$4',
      [String(nfeId), criacao.data?.data?.numero || '', extrairSituacaoNotaFiscal(criacao.data?.data), vendaId]
    );

    const envio = await requisicaoBling(`nfe/${nfeId}/enviar`, token, {
      method: 'POST',
      body: {}
    });

    if (envio.status < 200 || envio.status >= 300) {
      return res.status(400).json({
        erro: resumirErroBling(envio.data, 'Erro ao enviar NF-e'),
        detalhes: envio.data || envio.texto
      });
    }

    try {
      const cacheBling = {};
      const consulta = await consultarBlingPorId(`nfe/${nfeId}`, token);
      if (consulta.status >= 200 && consulta.status < 300 && consulta.data?.data) {
        const notaConsultada = await enriquecerSituacaoNotaFiscalBling(consulta.data.data, token, cacheBling);
        const situacaoAtual = extrairSituacaoNotaFiscal(notaConsultada);
        const situacaoDetalhada = extrairMotivoBling(consulta.data, situacaoAtual || '');
        const situacaoSalvar = situacaoAtual || situacaoDetalhada || '';
        await pool.query(
          `UPDATE vendas
           SET nfe_numero=COALESCE(NULLIF($1,''), nfe_numero),
               nfe_situacao=COALESCE(NULLIF($2,''), nfe_situacao)
           WHERE id=$3`,
          [notaConsultada.numero || '', situacaoSalvar, vendaId]
        );
        if (normalizarTextoBling(situacaoSalvar || situacaoAtual).includes('rejeit')) {
          return res.status(400).json({
            erro: `NF-e rejeitada no Bling${situacaoSalvar || situacaoAtual ? `: ${situacaoSalvar || situacaoAtual}` : '.'}`,
            detalhes: consulta.data,
            nfe: notaConsultada
          });
        }
        return res.json({ ok: true, nfe: notaConsultada });
      }
    } catch (errConsulta) {
      console.error('Erro ao consultar NF-e criada no Bling:', errConsulta);
    }

    res.json({ ok: true, nfe: criacao.data?.data });
  } catch (err) {
    console.error('Erro NF-e:', err);
    res.status(500).json({ erro: err.message });
  }
});

// Rota para emitir NFC-e
app.post('/api/bling/nfce', auth, async (req, res) => {
  try {
    const { vendaId } = req.body;

    const vendaRes = await pool.query(
      `SELECT v.*, c.nome as cli_nome, c.cpf, c.cnpj, c.ie, c.tipo as cli_tipo,
              e.logradouro, e.numero, e.complemento, e.bairro, e.cidade,
              COALESCE(NULLIF(e.uf, ''), NULLIF(e.estado, '')) as uf,
              e.cep
       FROM vendas v
       LEFT JOIN clientes c ON c.id = v.cliente_id
       LEFT JOIN enderecos_cliente e ON e.cliente_id = v.cliente_id AND e.principal = true
       WHERE v.id = $1`,
      [vendaId]
    );
    if (!vendaRes.rows.length) return res.status(404).json({ erro: 'Venda não encontrada' });
    const venda = vendaRes.rows[0];

    const itensRes = await pool.query(
      `SELECT vi.*, p.ncm, p.csosn
       FROM venda_itens vi
       LEFT JOIN produtos p ON p.id = vi.produto_id
       WHERE vi.venda_id = $1 AND vi.tipo != 'devolvido'`,
      [vendaId]
    );

    const pgtoRes = await pool.query(
      `SELECT tipo, valor, parcelas, vl_parcela, detalhe
       FROM venda_pagamentos
       WHERE venda_id = $1
       ORDER BY id`,
      [vendaId]
    );

    if (!itensRes.rows.length) {
      return res.status(400).json({ erro: 'Venda sem itens válidos para emitir NFC-e.' });
    }

    const itensSemNCM = itensRes.rows
      .filter(item => !normalizarNCM(item.ncm))
      .map(item => item.nome || item.cod || 'item sem identificação');
    if (itensSemNCM.length) {
      return res.status(400).json({ erro: 'Os seguintes produtos estão sem NCM: ' + itensSemNCM.join(', ') + '.' });
    }

    const token = await getBlingToken();
    const formasPagamentoBling = await listarFormasPagamentoBling(token);
    const documentoCliente = (venda.cpf || venda.cnpj || '').replace(/\D/g, '');
    const dataOperacao = new Date(venda.data).toISOString().split('T')[0];
    const indicadorPresenca = venda.canal === 'online' ? 4 : 1;
    const nomeCliente = venda.cli_nome || 'Consumidor Final';
    const clientePayload = (() => {
      const cliente = { nome: nomeCliente };
      if (documentoCliente) cliente.cpfCnpj = documentoCliente;
      return cliente;
    })();
    const contribuinte = 9;
    const contatoPayload = documentoCliente ? {
      nome: nomeCliente,
      tipoPessoa: venda.cli_tipo === 'PJ' ? 'J' : 'F',
      numeroDocumento: documentoCliente,
      contribuinte,
      endereco: {
        endereco: venda.logradouro || '',
        numero: venda.numero || 'S/N',
        complemento: venda.complemento || '',
        bairro: venda.bairro || '',
        cep: (venda.cep || '').replace(/\D/g, ''),
        municipio: venda.cidade || '',
        uf: venda.uf || '',
        pais: ''
      }
    } : null;
    if (venda.cli_tipo === 'PJ') {
      contatoPayload.ie = (venda.ie || '').trim() || 'ISENTO';
    }
    const vProd = itensRes.rows.reduce((acc, item) => acc + (parseFloat(item.preco) || 0) * (parseInt(item.qty) || 0), 0);
    const vNF = parseFloat(venda.tot) || 0;
    const fatorDesc = vProd > 0 && vNF < vProd ? vNF / vProd : 1;
    const itensPayload = itensRes.rows.map((item, idx) => {
      const quantidade = parseFloat(item.qty) || 0;
      const valorUnitario = Math.round((parseFloat(item.preco) || 0) * fatorDesc * 100) / 100;
      const valorTotal = Math.round(valorUnitario * quantidade * 100) / 100;
      const ncm = normalizarNCM(item.ncm);
      return {
        item: idx + 1,
        codigo: item.cod || '',
        descricao: item.nome || '',
        ncm,
        classificacaoFiscal: ncm,
        cfop: 5102,
        unidade: 'PC',
        quantidade,
        valor: valorUnitario,
        valorTotal,
        csosn: String(item.csosn || '102')
      };
    });
    const totalItens = Math.round(itensPayload.reduce((acc, item) => acc + item.valorTotal, 0) * 100) / 100;
    const pagamentos = (Array.isArray(pgtoRes.rows) ? pgtoRes.rows : [])
      .filter(pagamento => valorParaCentavos(pagamento.valor) > 0);
    const parcelasPayload = [];
    const proximoNumeroNFCe = await obterProximoNumeroFiscalBling('nfce', token);
    const totalItensCentavos = valorParaCentavos(totalItens);
    const somaPagamentosCentavos = pagamentos.reduce((acc, pagamento) => acc + valorParaCentavos(pagamento.valor), 0);
    let centavosAlocadosPagamentos = 0;

    pagamentos.forEach((pagamento, pagamentoIdx) => {
      const parcelas = Math.max(1, parseInt(pagamento.parcelas) || 1);
      const valorOriginalCentavos = valorParaCentavos(pagamento.valor);
      const ehUltimoPagamento = pagamentoIdx === pagamentos.length - 1;
      const valorPagamentoCentavos = somaPagamentosCentavos > 0
        ? (ehUltimoPagamento
            ? totalItensCentavos - centavosAlocadosPagamentos
            : Math.round(valorOriginalCentavos * totalItensCentavos / somaPagamentosCentavos))
        : 0;
      centavosAlocadosPagamentos += valorPagamentoCentavos;
      if (valorPagamentoCentavos <= 0) return;

      const formaPagamentoId = mapearFormaPagamentoBling(pagamento.tipo, formasPagamentoBling);
      const valorBaseCentavos = Math.floor(valorPagamentoCentavos / parcelas);

      for (let i = 0; i < parcelas; i++) {
        const valorParcelaCentavos = i < parcelas - 1
          ? valorBaseCentavos
          : valorPagamentoCentavos - valorBaseCentavos * (parcelas - 1);
        const parcela = {
          dias: i * 30,
          data: dataOperacao,
          valor: centavosParaValor(valorParcelaCentavos)
        };
        if (formaPagamentoId) {
          parcela.formaPagamento = { id: formaPagamentoId };
        }
        if (pagamento.detalhe) {
          parcela.observacoes = pagamento.detalhe;
        }
        parcelasPayload.push(parcela);
      }
    });

    if (!parcelasPayload.length) {
      parcelasPayload.push({
        dias: 0,
        data: dataOperacao,
        valor: totalItens
      });
    }

    const payload = {
      tipo: 1,
      dataOperacao,
      cfop: 5102,
      indicadorPresenca,
      itens: itensPayload,
      parcelas: parcelasPayload
    };
    if (proximoNumeroNFCe) payload.numero = proximoNumeroNFCe;
    if (contatoPayload) {
      payload.contato = contatoPayload;
    } else {
      payload.cliente = clientePayload;
    }

    const criacao = await requisicaoBling('nfce', token, {
      method: 'POST',
      body: payload
    });

    if (criacao.status < 200 || criacao.status >= 300) {
      return res.status(400).json({ erro: resumirErroBling(criacao.data, 'Erro ao emitir NFC-e'), detalhes: criacao.data || criacao.texto });
    }

    const nfceId = criacao.data?.data?.id;
    if (!nfceId) {
      return res.status(400).json({ erro: 'Bling não retornou o ID da NFC-e criada.', detalhes: criacao.data || criacao.texto });
    }

    const envio = await requisicaoBling(`nfce/${nfceId}/enviar`, token, {
      method: 'POST',
      body: {}
    });

    if (envio.status < 200 || envio.status >= 300) {
      return res.status(400).json({
        erro: resumirErroBling(envio.data, 'Erro ao enviar NFC-e'),
        detalhes: envio.data || envio.texto
      });
    }

    if (nfceId) {
      await pool.query(
        `UPDATE vendas SET nfce_id=$1, nfce_numero=$2, nfce_situacao=$3 WHERE id=$4`,
        [String(nfceId), criacao.data?.data?.numero || '', extrairSituacaoNotaFiscal(criacao.data?.data), vendaId]
      );
      try {
        const cacheBling = {};
        const consulta = await consultarBlingPorId(`nfce/${nfceId}`, token);
        if (consulta.status >= 200 && consulta.status < 300 && consulta.data?.data) {
          const notaConsultada = await enriquecerSituacaoNotaFiscalBling(consulta.data.data, token, cacheBling, 'nfce');
          const situacaoAtual = extrairSituacaoNotaFiscal(notaConsultada);
          const situacaoDetalhada = extrairMotivoBling(consulta.data, situacaoAtual || '');
          const situacaoSalvar = situacaoAtual || situacaoDetalhada || '';
          await pool.query(
            `UPDATE vendas
             SET nfce_numero=COALESCE(NULLIF($1,''), nfce_numero),
                 nfce_situacao=COALESCE(NULLIF($2,''), nfce_situacao)
             WHERE id=$3`,
            [notaConsultada.numero || '', situacaoSalvar, vendaId]
          );
          if (normalizarTextoBling(situacaoSalvar || situacaoAtual).includes('rejeit')) {
            return res.status(400).json({
              erro: `NFC-e rejeitada no Bling${situacaoSalvar || situacaoAtual ? `: ${situacaoSalvar || situacaoAtual}` : '.'}`,
              detalhes: consulta.data,
              nfce: notaConsultada
            });
          }
          return res.json({ ok: true, nfce: notaConsultada });
        }
      } catch (errConsulta) {
        console.error('Erro ao consultar NFC-e criada no Bling:', errConsulta);
      }
    }

    res.json({ ok: true, nfce: criacao.data?.data });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});
// ─────────────────────────────────────────────────────────────────────────────

// ─── BLING OAUTH 2.0 ─────────────────────────────────────────────────────────
const BLING_CLIENT_ID = process.env.BLING_CLIENT_ID;
const BLING_CLIENT_SECRET = process.env.BLING_CLIENT_SECRET;
const BLING_REDIRECT_URI = 'https://scap-moda-server-production.up.railway.app/api/bling/callback';
const BLING_AUTH_URL = 'https://www.bling.com.br/Api/v3/oauth/authorize';
const BLING_TOKEN_URL = 'https://www.bling.com.br/Api/v3/oauth/token';

// Rota para iniciar autorização — redireciona para o Bling
app.get('/api/bling/autorizar', (req, res) => {
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: BLING_CLIENT_ID,
    redirect_uri: BLING_REDIRECT_URI,
    state: 'scap-moda'
  });
  res.redirect(BLING_AUTH_URL + '?' + params.toString());
});

// Callback — Bling redireciona aqui com o código
app.get('/api/bling/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) {
    return res.redirect('/?bling=erro');
  }
  try {
    const credentials = Buffer.from(BLING_CLIENT_ID + ':' + BLING_CLIENT_SECRET).toString('base64');
    const response = await fetch(BLING_TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + credentials
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: BLING_REDIRECT_URI
      })
    });
    const data = await response.json();
    if (!data.access_token) throw new Error('Token não retornado');

    const expiresAt = new Date(Date.now() + (data.expires_in || 21600) * 1000);

    await pool.query(
      `INSERT INTO bling_tokens (id, access_token, refresh_token, expires_at, atualizado_em)
       VALUES (1, $1, $2, $3, NOW())
       ON CONFLICT (id) DO UPDATE SET access_token=$1, refresh_token=$2, expires_at=$3, atualizado_em=NOW()`,
      [data.access_token, data.refresh_token, expiresAt]
    );
    res.redirect('/?bling=conectado');
  } catch (err) {
    console.error('Erro Bling OAuth:', err.message);
    res.redirect('/?bling=erro');
  }
});

// Função para obter token válido (renova se expirado)
async function getBlingToken() {
  const r = await pool.query('SELECT * FROM bling_tokens WHERE id=1');
  if (!r.rows.length) throw new Error('Bling não autorizado. Conecte o Bling em Configurações.');

  const token = r.rows[0];
  const agora = new Date();

  // Renova se expirado ou expira em menos de 5 minutos
  if (new Date(token.expires_at) <= new Date(agora.getTime() + 5 * 60000)) {
    const credentials = Buffer.from(BLING_CLIENT_ID + ':' + BLING_CLIENT_SECRET).toString('base64');
    const response = await fetch(BLING_TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + credentials
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: token.refresh_token
      })
    });
    const data = await response.json();
    if (!data.access_token) throw new Error('Erro ao renovar token do Bling');

    const expiresAt = new Date(Date.now() + (data.expires_in || 21600) * 1000);
    await pool.query(
      `UPDATE bling_tokens SET access_token=$1, refresh_token=$2, expires_at=$3, atualizado_em=NOW() WHERE id=1`,
      [data.access_token, data.refresh_token, expiresAt]
    );
    return data.access_token;
  }
  return token.access_token;
}

// Rota para verificar status da conexão com Bling
app.get('/api/bling/status', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT expires_at, atualizado_em FROM bling_tokens WHERE id=1');
    if (!r.rows.length) return res.json({ conectado: false });
    res.json({
      conectado: true,
      expiresAt: r.rows[0].expires_at,
      atualizadoEm: r.rows[0].atualizado_em
    });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});
// ─────────────────────────────────────────────────────────────────────────────

initDB().then(() => {
  app.listen(PORT, () => console.log(`Scap Moda rodando na porta ${PORT}`));
  agendarBackupDiario();
});
