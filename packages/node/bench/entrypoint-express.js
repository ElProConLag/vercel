const express = require('express');
const escapeHtml = require('escape-html');

const app = express();

module.exports = app;

app.use(express.json());

app.post('*', (req, res) => {
  if (req.body == null) {
    return res.status(400).send({ error: 'no JSON object in the request' });
  }

  const sanitizedBody = escapeHtml(JSON.stringify(req.body, null, 4));
  return res.status(200).send(sanitizedBody);
});

app.all('*', (req, res) => {
  res.status(405).send({ error: 'only POST requests are accepted' });
});
