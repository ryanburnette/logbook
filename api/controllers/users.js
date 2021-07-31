'use strict';

var app = require('@root/async-router').Router();
var authorize = require('@ryanburnette/authorization');
var { User } = require('../models');

var findOneUser = require('@ryanburnette/find-one-record')({
  pkName: 'email',
  model: User
});

var authAdmin = authorize({ roles: ['admin'] });

app.get('/api/users', authAdmin, async function (req, res) {
  return await User.findAll();
});

app.post('/api/users', authAdmin, async function (req, res) {
  return await User.create(req.body);
});

app.get('/api/users/me', async function (req, res) {
  if (!req.user) {
    return res.sendStatus(401);
  }
  return req.user;
});

app.get('/api/users/:email', authAdmin, findOneUser, async function (req, res) {
  return req.record;
});

app.patch(
  '/api/users/:email',
  findOneUser,
  authAdmin,
  async function (req, res) {
    /* console.log(req.user); */
    Object.keys(req.body).forEach((k) => {
      req.record[k] = req.body[k];
    });
    return await req.record.save();
  }
);

app.delete(
  '/api/users/:email',
  findOneUser,
  authAdmin,
  async function (req, res) {
    return await req.record.destroy();
  }
);

module.exports = app;
