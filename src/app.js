// src/app.js - Aplicação Node.js com vulnerabilidades para SAST
const express = require('express');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
const xml2js = require('xml2js');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Configuração do banco de dados PostgreSQL
const pool = new Pool({
  host: process.env.DB_HOST_PROD || process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER_PROD || process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD_PROD || process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME_PROD || process.env.DB_NAME || 'testdb',
  port: process.env.DB_PORT_PROD || process.env.DB_PORT || 5432,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Testar conexão
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Erro ao conectar ao banco de dados:', err);
  } else {
    console.log('Conectado ao PostgreSQL:', res.rows[0]);
  }
});

// Rota raiz
app.get('/', (req, res) => {
  res.json({ 
    message: 'API SAST - Aplicação de teste para análise de segurança',
    version: '1.0.0',
    endpoints: ['/users/:id', '/search', '/upload', '/xml']
  });
});

// Rota com SQL Injection (vulnerabilidade intencional)
app.get('/users/:id', (req, res) => {
  const userId = req.params.id;
  // VULNERABILIDADE: SQL Injection - não usa prepared statements
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  
  pool.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Erro no banco de dados' });
    }
    res.json(results.rows);
  });
});

// Rota com Command Injection (vulnerabilidade intencional)
app.get('/search', (req, res) => {
  const searchTerm = req.query.term;
  // VULNERABILIDADE: Command Injection
  const { exec } = require('child_process');
  exec(`grep -r "${searchTerm}" ./`, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: 'Erro na busca' });
    }
    res.json({ results: stdout });
  });
});

// Rota com Path Traversal (vulnerabilidade intencional)
app.get('/file', (req, res) => {
  const fileName = req.query.name;
  // VULNERABILIDADE: Path Traversal
  const fs = require('fs');
  fs.readFile(`./uploads/${fileName}`, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).json({ error: 'Arquivo não encontrado' });
    }
    res.send(data);
  });
});

// Rota com XXE (vulnerabilidade intencional)
app.post('/xml', (req, res) => {
  const xmlData = req.body.xml;
  // VULNERABILIDADE: XXE - XML External Entity
  const parser = new xml2js.Parser({
    explicitArray: false,
    // Não desabilita entidades externas
  });
  
  parser.parseString(xmlData, (err, result) => {
    if (err) {
      return res.status(400).json({ error: 'XML inválido' });
    }
    res.json(result);
  });
});

// Rota com hardcoded credentials (vulnerabilidade intencional)
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // VULNERABILIDADE: Credenciais hardcoded
  const adminUser = 'admin';
  const adminPass = 'admin123';
  
  if (username === adminUser && password === adminPass) {
    res.json({ success: true, message: 'Login realizado' });
  } else {
    res.status(401).json({ success: false, message: 'Credenciais inválidas' });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

const PORT = process.env.PORT || 3000;

// Só inicia o servidor se não estiver em ambiente de teste
if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
  });
}

module.exports = app;
