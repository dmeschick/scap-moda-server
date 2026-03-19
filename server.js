const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
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

function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ erro: 'Não autorizado' });
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
      detalhe VARCHAR(200)
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
    const cpfDigitos = (func.cpf || '').replace(/\D/g, '');
    const senhaPadrao = cpfDigitos.length >= 4 ? cpfDigitos.slice(0, 4) : '1234';
    const ok = func.senha_hash ? await bcrypt.compare(senha, func.senha_hash) : senha === senhaPadrao;
    if (!ok) return res.status(401).json({ erro: 'Senha incorreta' });
    const token = jwt.sign({ id: func.id, nome: func.nome, cargo: func.cargo }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, funcionario: { id: func.id, nome: func.nome, cargo: func.cargo } });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});

// FUNCIONÁRIOS
app.get('/api/funcionarios', async (req, res) => {
  try {
    const { todos } = req.query;
    const sql = todos
      ? 'SELECT id,nome,cpf,cargo,tel,salario,comissao,admissao,turno,obs,status,foto FROM funcionarios ORDER BY nome'
      : "SELECT id,nome,cpf,cargo,tel,salario,comissao,admissao,turno,obs,status,foto FROM funcionarios WHERE status='ativo' ORDER BY nome";
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
    const hash = await bcrypt.hash(req.body.senha, 10);
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
    const sql = `SELECT * FROM produtos WHERE ${where.join(' AND ')} ORDER BY nome LIMIT ${parseInt(limit)||500} OFFSET ${parseInt(offset)||0}`;
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
app.patch('/api/produtos/:id/estoque', auth, async (req, res) => {
  try {
    const { delta } = req.body;
    await pool.query('UPDATE produtos SET est=GREATEST(0,est+$1),atualizado_em=NOW() WHERE id=$2', [delta, req.params.id]);
    const r = await pool.query('SELECT est FROM produtos WHERE id=$1', [req.params.id]);
    res.json({ est: r.rows[0]?.est });
  } catch (err) { res.status(500).json({ erro: err.message }); }
});


// CLIENTES
app.get('/api/clientes', auth, async (req, res) => {
  try {
    const { q } = req.query;
    let where = ['1=1'];
    let params = [];
    if (q) { where.push(`(LOWER(c.nome) LIKE $1 OR c.cpf LIKE $1 OR c.tel LIKE $1)`); params.push('%'+q.toLowerCase()+'%'); }
    const sql = `
      SELECT c.*, 
        COALESCE(json_agg(e.* ORDER BY e.principal DESC) FILTER (WHERE e.id IS NOT NULL), '[]') as enderecos
      FROM clientes c
      LEFT JOIN enderecos_cliente e ON e.cliente_id=c.id
      WHERE ${where.join(' AND ')}
      GROUP BY c.id ORDER BY c.nome`;
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
    await pool.query("UPDATE clientes SET status='inativo' WHERE id=$1", [req.params.id]);
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
        COALESCE(json_agg(DISTINCT jsonb_build_object('tipo',vp.tipo,'valor',vp.valor,'parcelas',vp.parcelas,'detalhe',vp.detalhe)) FILTER (WHERE vp.id IS NOT NULL),'[]') as pgto_itens
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
    await client.query(`INSERT INTO vendas (id,num,data,cliente_id,cliente_nome,vendedor_id,vendedor_nome,canal,subtotal,desconto,credito,tot,pag,obs,tipo,status)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
      [v.id,v.num,v.data,v.clienteId,v.clienteNome,v.vendedorId,v.vendedorNome,v.canal,v.sub||v.subtotal,v.desc||v.desconto||0,v.credito||0,v.tot,v.pag,v.obs,v.tipo||'venda',v.status||'pago']);
    for (const item of (v.itens||[])) {
      await client.query('INSERT INTO venda_itens (venda_id,produto_id,nome,cod,preco,qty,tipo) VALUES ($1,$2,$3,$4,$5,$6,$7)',
        [v.id,item.id,item.nome,item.cod,item.preco,item.qty,item.tipo||'novo']);
      if (item.tipo !== 'devolvido') {
        await client.query('UPDATE produtos SET est=GREATEST(0,est-$1),atualizado_em=NOW() WHERE id=$2', [item.qty, item.id]);
      }
    }
    for (const p of (v.pgtoItens||[])) {
      await client.query('INSERT INTO venda_pagamentos (venda_id,tipo,valor,parcelas,vl_parcela,troco,detalhe) VALUES ($1,$2,$3,$4,$5,$6,$7)',
        [v.id,p.tipo,p.valor,p.parcelas||1,p.vlParcela||p.valor,p.troco||0,p.detalhe||'']);
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
    res.json(r.rows[0]?.valor || null);
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
      pool.query(`SELECT COUNT(*) as total_vendas,SUM(tot) as faturamento,AVG(tot) as ticket_medio,
        COUNT(*) FILTER (WHERE canal='presencial') as presencial,COUNT(*) FILTER (WHERE canal='online') as online
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
    const hash = await bcrypt.hash(req.body.senha, 10);
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






















initDB().then(() => app.listen(PORT, () => console.log(`Scap Moda rodando na porta ${PORT}`)));
