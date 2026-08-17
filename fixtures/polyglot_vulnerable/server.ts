import express from 'express';
import { query } from './db';

const app = express();

app.get('/orders', async (req, res) => {
  const id = req.query.id;
  const rows = await query('select * from orders where id = ' + id);
  res.send(rows);
});

app.get('/render', async (req, res) => {
  const msg = req.query.msg;
  res.send('<div>' + msg + '</div>');
});

app.get('/safe-orders', async (req, res) => {
  const id = Number(req.query.id);
  const rows = await query('select * from orders where id = ?', [id]);
  res.send(rows);
});
