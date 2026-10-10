'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const https = require('node:https');
const { EventEmitter } = require('node:events');
const { probeSeller, validateTarget } = require('../lib/probe');

const record = (manifest, llms_txt) => ({
  slug: 'synthetic',
  payTo: '0x0000000000000000000000000000000000000001',
  endpoints: [{ url: 'https://127.0.0.1/private', method: 'GET' }],
  manifest, llms_txt,
});

test('untrusted private discovery destinations never open sockets', async () => {
  const old = https.request;
  let calls = 0;
  https.request = () => { calls++; throw Error('Forbidden synthetic socket'); };
  try {
    await probeSeller(record('https://127.0.0.1/manifest',
                             'https://127.0.0.1/llms.txt'));
    assert.equal(calls, 0);
  } finally {
    https.request = old;
  }
});

test('tailnet, embedded-credential and mixed DNS destinations are rejected', async () => {
  await assert.rejects(validateTarget('https://100.90.10.25/private'), /private/);
  await assert.rejects(validateTarget('https://name:password@93.184.216.34/'), /credential/);
  const dns = require('node:dns').promises;
  const prior = dns.lookup;
  dns.lookup = async () => [
    { address: '93.184.216.34', family: 4 },
    { address: '10.0.0.10', family: 4 },
  ];
  try {
    await assert.rejects(
      validateTarget('https://synthetic-example.invalid/private'),
      /private or reserved/
    );
  } finally {
    dns.lookup = prior;
  }
});

test('public HTTPS discovery uses pinned verified IP and retains normal behavior', async () => {
  const old = https.request;
  const calls = [];
  https.request = (url, options, callback) => {
    calls.push(String(url));
    assert.equal(typeof options.lookup, 'function');
    options.lookup('synthetic', {}, (err, address, family) => {
      assert.ifError(err);
      assert.equal(address, '93.184.216.34');
      assert.equal(family, 4);
    });
    const req = new EventEmitter();
    req.write = () => {};
    req.end = () => {
      process.nextTick(() => {
        const res = new EventEmitter();
        res.statusCode = 200;
        res.headers = {};
        callback(res);
        res.emit('data', Buffer.from('Public synthetic documentation'));
        res.emit('end');
      });
    };
    req.destroy = () => {};
    return req;
  };
  try {
    await probeSeller(record('https://93.184.216.34/manifest',
                             'https://93.184.216.34/llms.txt'));
    assert.equal(calls.length, 2);
    assert(calls.every((url) => url.startsWith('https://93.184.216.34/')));
  } finally {
    https.request = old;
  }
});
