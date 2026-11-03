'use strict';
// sqli-ml-guard — char n-gram TF-IDF + logistic-regression SQL injection
// detector as pure-JS Express middleware. No Python service at request time.

const { sqliGuard, stringValues } = require('./src/sqliGuard');
const { probaRaw, model, loadModel } = require('./src/model');
const { normalize } = require('./src/normalize');

module.exports = { sqliGuard, probaRaw, model, loadModel, normalize, stringValues };
