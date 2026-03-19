const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();
console.log('DATABASE_URL:', process.env.DATABASE_URL?.slice(0, 30));

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));

// Banco de dados
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const JWT_SECRET = process.env.JWT_SECRET || 'scap-moda-secret-2024';

// ========== MIDDLEWARE AUTH ==========
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ erro: 'Não autorizado' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ erro: 'Token inválido' });
  }
}

// ========== INIT BANCO ==========
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS dados (
      chave VARCHAR(100) PRIMARY KEY,
      valor JSONB NOT NULL,
      atualizado_em TIMESTAMP DEFAULT NOW()
    );
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
  `);
  console.log('Banco inicializado!');
}

// ========== LOGIN ==========
app.post('/api/login', async (req, res) => {
  try {
    const { funcId, senha } = req.body;
    const result = await pool.query('SELECT * FROM funcionarios WHERE id=$1 AND status=$2', [funcId, 'ativo']);
    if (!result.rows.length) return res.status(401).json({ erro: 'Funcionário não encontrado' });
    
    const func = result.rows[0];
    const cpfDigitos = (func.cpf || '').replace(/\D/g, '');
    const senhaPadrao = cpfDigitos.length >= 4 ? cpfDigitos.slice(0, 4) : '1234';
    
    let senhaOk = false;
    if (func.senha_hash) {
      senhaOk = await bcrypt.compare(senha, func.senha_hash);
    } else {
      senhaOk = senha === senhaPadrao;
    }
    
    if (!senhaOk) return res.status(401).json({ erro: 'Senha incorreta' });
    
    const token = jwt.sign({ id: func.id, nome: func.nome, cargo: func.cargo }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token, funcionario: { id: func.id, nome: func.nome, cargo: func.cargo } });
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});

// ========== DADOS GERAIS (produtos, clientes, vendas, etc) ==========
app.get('/api/dados/:chave', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT valor FROM dados WHERE chave=$1', [req.params.chave]);
    res.json(result.rows[0]?.valor || null);
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});

app.post('/api/dados/:chave', auth, async (req, res) => {
  try {
    await pool.query(`
      INSERT INTO dados (chave, valor, atualizado_em) VALUES ($1, $2, NOW())
      ON CONFLICT (chave) DO UPDATE SET valor=$2, atualizado_em=NOW()
    `, [req.params.chave, JSON.stringify(req.body.valor)]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});

// ========== FUNCIONÁRIOS ==========
app.get('/api/funcionarios', auth, async (req, res) => {
  try {
    const result = await pool.query('SELECT id,nome,cpf,cargo,tel,salario,comissao,admissao,turno,obs,status FROM funcionarios ORDER BY nome');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});

app.post('/api/funcionarios', auth, async (req, res) => {
  try {
    const f = req.body;
    await pool.query(`
      INSERT INTO funcionarios (id,nome,cpf,cargo,tel,salario,comissao,admissao,turno,obs,status)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      ON CONFLICT (id) DO UPDATE SET nome=$2,cpf=$3,cargo=$4,tel=$5,salario=$6,comissao=$7,admissao=$8,turno=$9,obs=$10,status=$11
    `, [f.id, f.nome, f.cpf, f.cargo, f.tel, f.salario||0, f.comissao||0, f.admissao||null, f.turno, f.obs, f.status||'ativo']);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});

app.put('/api/funcionarios/:id/senha', auth, async (req, res) => {
  try {
    const hash = await bcrypt.hash(req.body.senha, 10);
    await pool.query('UPDATE funcionarios SET senha_hash=$1 WHERE id=$2', [hash, req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});

// ========== BACKUP IMPORT ==========
app.post('/api/importar-backup', async (req, res) => {
  try {
    const dados = req.body;
    const chaves = ['produtos','clientes','fornecedores','categorias','vendas','descontos','config','trocas_pendentes'];
    for (const chave of chaves) {
      if (dados[chave] !== undefined) {
        await pool.query(`
          INSERT INTO dados (chave, valor, atualizado_em) VALUES ($1, $2, NOW())
          ON CONFLICT (chave) DO UPDATE SET valor=$2, atualizado_em=NOW()
        `, [chave, JSON.stringify(dados[chave])]);
      }
    }
    // Importa funcionários
    if (dados.funcionarios) {
      for (const f of dados.funcionarios) {
        await pool.query(`
          INSERT INTO funcionarios (id,nome,cpf,cargo,tel,salario,comissao,admissao,turno,obs,status)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
          ON CONFLICT (id) DO UPDATE SET nome=$2,cpf=$3,cargo=$4,tel=$5,salario=$6,comissao=$7,admissao=$8,turno=$9,obs=$10,status=$11
        `, [f.id,f.nome,f.cpf,f.cargo,f.tel,f.salario||0,f.comissao||0,f.admissao||null,f.turno,f.obs,f.status||'ativo']);
      }
    }
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
app.get('/api/debug-funcionarios', async (req, res) => {
  try {
    const r = await pool.query('SELECT id, nome, cargo, status FROM funcionarios');
    res.json(r.rows);
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});
initDB().then(() => {
  app.listen(PORT, () => console.log(`Scap Moda rodando na porta ${PORT}`));
});
