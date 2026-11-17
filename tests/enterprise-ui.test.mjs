import test from 'node:test';
import assert from 'node:assert/strict';
import {matchesDemoRecord} from '../enterprise-v2-filter.mjs';

const record = { text: 'app.example.test Production Outdated service version Critical Needs verification', severity: 'Critical' };

test('matches demo asset text case-insensitively', () => {
  assert.equal(matchesDemoRecord(record, 'APP.EXAMPLE.TEST'), true);
  assert.equal(matchesDemoRecord(record, '  production  '), true);
  assert.equal(matchesDemoRecord(record, 'not-there'), false);
});

test('filters by severity without bypassing query', () => {
  assert.equal(matchesDemoRecord(record, '', 'critical'), true);
  assert.equal(matchesDemoRecord(record, '', 'high'), false);
  assert.equal(matchesDemoRecord(record, 'invalid', 'critical'), false);
});

test('all severities shows every matching record', () => {
  assert.equal(matchesDemoRecord(record, '', 'all'), true);
  assert.equal(matchesDemoRecord({text:'another',severity:'medium'}, '', 'ALL'), true);
});

test('handles missing optional text or severity safely', () => {
  assert.equal(matchesDemoRecord({}, ''), true);
  assert.equal(matchesDemoRecord({}, 'example'), false);
  assert.equal(matchesDemoRecord({}, '', 'critical'), false);
});
