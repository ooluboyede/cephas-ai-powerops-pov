const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');

test('PoV shell and all primary workspaces are present', () => {
  for (const id of ['overview', 'findings', 'cases', 'reconciliation', 'reports', 'data', 'controls']) {
    assert.match(html, new RegExp('id="page-' + id + '"'));
  }
});

test('synthetic data boundary is visible', () => {
  assert.match(html, /SYNTHETIC DATA/);
  assert.match(html, /No live utility systems are connected/);
  assert.match(html, /not proof of theft or customer liability/);
});

test('no enterprise connection configuration is embedded', () => {
  assert.doesNotMatch(html, /DATABASE_URL|POSTGRES_URL|AWS_SECRET_ACCESS_KEY|BEGIN PRIVATE KEY/);
  assert.doesNotMatch(html, /api\.ibedc|ibedc\.com\.ng\/api/i);
});

test('human decision and financial-action guardrails are visible', () => {
  assert.match(html, /No autonomous disconnection/);
  assert.match(html, /No automatic bill adjustment/);
  assert.match(html, /Maker-checker/);
});

test('seed records remain synthetic fixture data', () => {
  assert.match(html, /const seed = \[/);
  assert.match(html, /F-RA-1042/);
});
