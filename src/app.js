// src/app.js - Aplicação Node.js com vulnerabilidades para SAST
const express = require('express');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
const xml2js = require('xml2js');
const crypto = require('crypto');
const { exec } = require('child_process');
const fs = require('fs');
const http = require('http');
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
    version: '1.0.0'
  });
});

// VULNERABILIDADE: SQL Injection
app.get('/users/:id', (req, res) => {
  const userId = req.params.id;
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  
  pool.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message, stack: err.stack });
    }
    res.json(results.rows);
  });
});

// VULNERABILIDADE: SQL Injection no login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  
  pool.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (results.rows.length > 0) {
      res.json({ success: true, user: results.rows[0] });
    } else {
      res.status(401).json({ success: false });
    }
  });
});

// VULNERABILIDADE: Command Injection
app.post('/execute', (req, res) => {
  const { command } = req.body;
  exec(command, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ error: error.message, stderr });
    }
    res.json({ output: stdout });
  });
});

// VULNERABILIDADE: Path Traversal
app.get('/download', (req, res) => {
  const fileName = req.query.file;
  const filePath = `./uploads/${fileName}`;
  
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).json({ error: 'File not found' });
    }
    res.send(data);
  });
});

// VULNERABILIDADE: XSS
app.get('/search', (req, res) => {
  const query = req.query.q;
  res.send(`<h1>Search results for: ${query}</h1>`);
});

// VULNERABILIDADE: Weak Cryptography
app.post('/encrypt', (req, res) => {
  const { data } = req.body;
  const cipher = crypto.createCipher('des', 'weak-key');
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  res.json({ encrypted, algorithm: 'DES' });
});

// VULNERABILIDADE: SSRF
app.get('/fetch-url', (req, res) => {
  const url = req.query.url;
  http.get(url, (response) => {
    let data = '';
    response.on('data', (chunk) => { data += chunk; });
    response.on('end', () => { res.json({ content: data }); });
  }).on('error', (err) => {
    res.status(500).json({ error: err.message });
  });
});

// VULNERABILIDADE: Code Injection via eval
app.post('/calculate', (req, res) => {
  const { expression } = req.body;
  try {
    const result = eval(expression);
    res.json({ result });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// VULNERABILIDADE: ReDoS
app.get('/validate-email', (req, res) => {
  const email = req.query.email;
  const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
  const isValid = emailRegex.test(email);
  res.json({ email, valid: isValid });
});

// VULNERABILIDADE: Insecure Random
app.get('/generate-token', (req, res) => {
  const token = Math.random().toString(36).substring(2);
  res.json({ token });
});

// VULNERABILIDADE: Prototype Pollution
app.post('/merge', (req, res) => {
  const { target, source } = req.body;
  const merge = (obj1, obj2) => {
    for (let key in obj2) {
      obj1[key] = obj2[key];
    }
    return obj1;
  };
  const result = merge(target || {}, source || {});
  res.json({ result });
});

// VULNERABILIDADE: Mass Assignment
app.post('/users', (req, res) => {
  const userData = req.body;
  res.json({ created: true, user: userData });
});

// VULNERABILIDADE: Timing Attack
app.post('/verify-token', (req, res) => {
  const { token } = req.body;
  const validToken = 'secret-token-12345';
  let isValid = token === validToken;
  res.json({ valid: isValid });
});

// Error handler que expõe detalhes
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    details: err
  });
});

const PORT = process.env.PORT || 3000;

if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
  });
}

module.exports = app;
