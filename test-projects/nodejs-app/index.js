const express = require('express');
const lodash = require('lodash');
const axios = require('axios');
const moment = require('moment');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

app.use(express.json());

// Sample endpoint using vulnerable dependencies
app.get('/', (req, res) => {
  const data = {
    timestamp: moment().format(),
    users: lodash.range(1, 10).map(id => ({ id, name: `User ${id}` })),
    message: 'Test application for OSS compliance scanning'
  };
  
  res.json(data);
});

app.get('/external', async (req, res) => {
  try {
    const response = await axios.get('https://jsonplaceholder.typicode.com/posts/1');
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  // Using deprecated/vulnerable JWT signing
  const token = jwt.sign({ username }, 'secret-key', { expiresIn: '1h' });
  
  res.json({ token });
});

app.listen(port, () => {
  console.log(`Test app listening at http://localhost:${port}`);
}); 