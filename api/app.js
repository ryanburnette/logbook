(async function () {
  'use strict';

  require('dotenv').config({});
  var express = require('express');
  var { Router } = require('@root/async-router');
  var bodyParser = require('body-parser');
  var helmet = require('helmet');
  var morgan = require('morgan');
  var http = require('http');
  var fs = require('fs').promises;
  var privkey = await fs.readFile('.key.jwk.json', 'utf8');
  var Auth3000 = require('auth3000');
  var issuer = process.env.BASE_URL || 'http://localhost:3000';
  var db = require('./models');

  var app = Router();

  var sessionMiddleware = Auth3000(issuer, privkey, async function (req) {
    var { strategy, email, iss, ppid, oidc_claims } = req.authn;

    var user;
    switch (strategy) {
      case 'challenge':
        user = await db.User.findOne({ where: { email } }).then((record) => {
          record = record.get({ plain: true });
          record.roles = record.roles.split(',');
          return record;
        });
        break;
      case 'refresh':
        var { jws } = req.authn;
        user = await db.User.findOne({ where: { email: jws.claims.sub } }).then(
          (record) => {
            record = record.get({ plain: true });
            record.roles = record.roles.split(',');
            return record;
          }
        );
        break;
      default:
        throw new Error('unsupported auth strategy');
    }

    if (!user) {
      var err = new Error('user not found');
      throw err;
    }

    return {
      claims: { sub: user.email },
      access_claims: { name: user.name, roles: user.roles }
    };
  });
  sessionMiddleware.challenge({
    store: {
      set: async function (id, attrs) {
        var [record, created] = await db.Session.findOrCreate({
          where: { id }
        });
        record.attrs = attrs;
        return await record.save();
      },
      get: async function (id) {
        var record = await db.Session.findOne({ where: { id } });
        if (record) {
          return record.get({ plain: true }).attrs;
        }
        return false;
      }
    },
    notify: async function (req) {
      var { strategy, type, value, secret, id, issuer, jws } = req.authn;
      var email = value;

      if (strategy !== 'challenge') {
        let message = `${strategy} is not a supported strategy`;
        let err = new Error(message);
        err.response = {
          statusCode: 400,
          json: {
            message,
            strategy
          }
        };
        throw err;
      }

      var user = await db.User.findOne({ where: { email } });
      if (!user) {
        let message = `User ${email} is not authorized to log in. The administrator has been notified of the attempt.`;
        let err = new Error(message);
        err.res = {
          statusCode: 400,
          json: { message, email, code: 'UNAUTHORIZED' }
        };
        throw err;
      }

      var url = `${issuer}/admin/#/login?secret=${id}.${secret}`;

      switch (process.env.NODE_ENV) {
        case 'development':
          console.log('###  NOTIFY ###');
          console.log(req.authn);
          console.log(url);
          console.log('### /NOTIFY ###');
          break;
        default:
          let rnd = hat();
          await transporter
            .sendMail({
              from: 'Delta ALPA EBB <no-reply@localhost>',
              to: email,
              subject: 'Verify your email address',
              text: url,
              html: `<p>If you just tried to log in to localhost, click the link to verify your email address.</p><a href="${url}">${url}</a>`,
              'h:Message-ID': rnd + '@localhost',
              'h:X-Entity-Ref-ID': rnd + '@localhost',
              'h:References': rnd + '@localhost'
            })
            .catch(console.error);
          break;
      }
    }
  });
  sessionMiddleware.credentials();

  // /api/authn/{session,refresh,exchange,challenge,logout}
  app.use('/api/authn', await sessionMiddleware.router());
  // /.well-known/openid-configuration
  app.use('/', await sessionMiddleware.wellKnown());

  // verify tokens
  var authnMiddleware = require('auth3000/middleware/');
  /* app.use('/api', authnMiddleware({ iss: issuer })); */
  app.use('/api', authnMiddleware({ iss: issuer, optional: true }));

  // controllers
  app.use(require('./controllers/users'));
  /* app.use(require('./controllers/flights')); */
  /* app.use(require('./controllers/aircraft')); */
  /* app.use(require('./controllers/approaches')); */
  /* app.use(require('./controllers/pilots')); */

  // errors
  app.use(async function (err, req, res, next) {
    // todo
    next(err);
  });

  // server
  var server = express();
  server.set('trust proxy', true);
  server.use(morgan('combined'));
  server.use(helmet());
  server.use(bodyParser.json());
  server.use(app);
  http.createServer(server).listen(process.env.PORT || 3001, function () {
    console.log('listening', process.env.PORT || 3001);
  });
})();
