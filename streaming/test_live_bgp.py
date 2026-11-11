"""Authored protocol fixtures only; no production feed traffic or personal data."""
import json
import unittest
from live_bgp import ASNMap, BGPConfig, WindowAggregator, strict_json


def frame(origin=64500, uid='fixture-1', stamp=1001, withdrawals=None):
    return json.dumps({'type': 'ris_message', 'data': {
        'type': 'UPDATE', 'host': 'rrc21', 'id': uid, 'timestamp': stamp,
        'peer': '192.0.2.1', 'path': [64496, origin],
        'announcements': [] if withdrawals else [{'prefixes': ['203.0.113.0/24']}],
        'withdrawals': withdrawals or []}})


class BGPTests(unittest.TestCase):
    def make(self, **kwargs):
        return WindowAggregator(BGPConfig(collector='rrc21', **kwargs), ASNMap({64500: 'FR', 64501: 'DE'}))

    def test_activation_requires_scope_terms_and_capacity(self):
        self.assertIsNotNone(BGPConfig.from_env({}).gate)
        self.assertIsNotNone(BGPConfig(enabled=True, terms_accepted=True, capacity_approved=True).gate)
        cfg=BGPConfig(enabled=True, terms_accepted=True, capacity_approved=True, collector='rrc21', prefixes=('203.0.113.0/24',))
        self.assertIsNone(cfg.gate)
        self.assertFalse(cfg.subscription()['data']['socketOptions']['includeRaw'])

    def test_real_input_is_required_and_deduplicated(self):
        agg=self.make(); self.assertEqual(agg.flush(1000), [])
        self.assertEqual(agg.feed(frame(),1001),'accepted')
        self.assertEqual(agg.feed(frame(),1002),'duplicate')
        event,evidence=agg.flush(1010)[0]
        self.assertEqual((event['country'],event['value']),('FR',1))
        self.assertNotIn('192.0.2.1',json.dumps(evidence))
        self.assertNotIn('fixture-1',json.dumps(evidence))
        self.assertEqual(evidence['sample_count'],1)

    def test_ambiguous_origin_and_withdrawals_are_unlocated(self):
        for raw in [frame(origin=[64500,64501]),frame(withdrawals=['203.0.113.0/24'])]:
            agg=self.make();agg.feed(raw,1001)
            self.assertNotIn('country',agg.flush(1010)[0][0])

    def test_origin_change_requires_same_retained_route(self):
        agg=self.make();agg.feed(frame(),1001)
        agg.feed(frame(64501,'fixture-2',1002),1002)
        rows=agg.flush(1010)
        self.assertEqual(sum(e['type']=='routing_anomaly_candidate' for e,_ in rows),1)
        agg.gap();agg.feed(frame(64500,'fixture-3',1011),1011)
        self.assertFalse(any(e['type']=='routing_anomaly_candidate' for e,_ in agg.flush(1020)))

    def test_rejects_stale_invalid_oversized_and_overflow(self):
        agg=self.make(max_buckets=1)
        self.assertEqual(agg.feed(frame(stamp=1),1001),'rejected')
        self.assertEqual(agg.feed('{"type":NaN}',1001),'rejected')
        with self.assertRaises(ValueError): strict_json('x'*65537)
        agg.feed(frame(),1001)
        self.assertEqual(agg.feed(frame(64501,'fixture-2',1002),1002),'rejected')
        self.assertEqual(agg.flush(1010),[])

    def test_mapping_excludes_non_authoritative_and_unknown(self):
        raw=json.dumps([{'asn':64500,'metadata':{'origin':'authoritative','countryCode':'FR'}},
                        {'asn':64501,'metadata':{'origin':'inferred','countryCode':'DE'}}]).encode()
        compiled=ASNMap.compile(raw,'a'*40)
        self.assertEqual(compiled['entries'],{'64500':'FR'})
        self.assertEqual(len(compiled['metadata']['source_sha256']),64)

if __name__=='__main__': unittest.main()

