"""Bounded retention, public replay coverage, reference enrichment and request limits."""
import asyncio
from collections import OrderedDict, deque
import json
import os
import time
from contextlib import suppress
import httpx
from fastapi.responses import JSONResponse

SCHEMA = """
CREATE TABLE IF NOT EXISTS retention_state (
 singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),
 pruned_public_seq BIGINT NOT NULL DEFAULT 0);
INSERT INTO retention_state(singleton) VALUES(TRUE) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS collector_checkpoints(source TEXT PRIMARY KEY, until_ts BIGINT NOT NULL);
"""

async def replay_coverage(pool, after, public):
    async with pool.acquire() as db:
        watermark = await db.fetchval('SELECT pruned_public_seq FROM retention_state WHERE singleton')
    return {'replay_gap': bool(after and after < watermark),
            'pruned_through_seq': watermark,
            'gap_reason': 'Local retention expired; some observations are no longer replayable' if after and after < watermark else None}

async def maintenance(pool, public):
    while True:
        try:
            async with pool.acquire() as db:
                async with db.transaction():
                    rows = await db.fetch("""DELETE FROM observations WHERE seq IN (
                      SELECT seq FROM observations WHERE received_at < now()-interval '48 hours'
                      OR seq <= (SELECT COALESCE(max(seq),0)-20000 FROM observations)
                      ORDER BY seq LIMIT 5000) RETURNING seq,feed_source""")
                    visible=[r['seq'] for r in rows if public or r['feed_source'] not in ('urlhaus','threatfox','Feodotracker')]
                    if visible:
                        await db.execute('UPDATE retention_state SET pruned_public_seq=GREATEST(pruned_public_seq,$1)',max(visible))
                    await db.execute("DELETE FROM coverage_gaps WHERE observed_at<now()-interval '7 days'")
        except asyncio.CancelledError:
            raise
        except Exception:
            # The health probe reports database failure; never terminate maintenance silently.
            import logging
            logging.exception('Retention maintenance failed')
        await asyncio.sleep(60)

async def epss(pool, health):
    """Daily EPSS for the 100 most recently added KEVs, never an observed attack."""
    while True:
        try:
            async with pool.acquire() as db:
                value=await db.fetchval("SELECT payload FROM reference_datasets WHERE source='cisa_kev'")
            if not value:
                await asyncio.sleep(30)
                continue
            kev=json.loads(value) if isinstance(value,str) else value
            recent=sorted(kev['vulnerabilities'],key=lambda v:v.get('dateAdded',''),reverse=True)[:100]
            cves=','.join(v['cveID'] for v in recent)
            async with httpx.AsyncClient(timeout=30) as client:
                response=await client.get('https://api.first.org/data/v1/epss',params={'cve':cves,'limit':100})
                response.raise_for_status()
                payload=response.json()
            if not isinstance(payload.get('data'),list): raise ValueError('Invalid EPSS schema')
            async with pool.acquire() as db:
                await db.execute("""INSERT INTO reference_datasets(source,fetched_at,source_date,payload)
                  VALUES('first_epss',now(),$1,$2::jsonb) ON CONFLICT(source) DO UPDATE
                  SET fetched_at=now(),source_date=$1,payload=$2::jsonb""",
                  payload['data'][0].get('date') if payload['data'] else None,json.dumps(payload))
            await health('first_epss','reference_current')
        except asyncio.CancelledError: raise
        except Exception as exc: await health('first_epss','degraded',type(exc).__name__)
        await asyncio.sleep(86400)

def install(app, get_pool, public):
    clients=OrderedDict()
    def allowed(ip, limit=120):
        now=time.monotonic()
        bucket=clients.setdefault(ip,deque())
        clients.move_to_end(ip)
        while bucket and bucket[0]<now-60: bucket.popleft()
        if len(clients)>2048: clients.popitem(last=False)
        if len(bucket)>=limit: return False
        bucket.append(now)
        return True
    app.state.allow_request=allowed

    @app.middleware('http')
    async def request_limit(request, call_next):
        # Caddy overwrites this header; the API is bound only to loopback.
        ip=request.headers.get('x-real-ip') or request.client.host
        if not allowed(ip): return JSONResponse({'detail':'Rate limit exceeded'},429,headers={'Retry-After':'60'})
        response=await call_next(request)
        response.headers['Cache-Control']='no-store'
        return response

    @app.get('/api/ready')
    async def ready():
        try:
            async with get_pool().acquire() as db: await db.fetchval('SELECT 1')
            return {'ready':True}
        except Exception: return JSONResponse({'ready':False},503)

    @app.get('/api/references')
    async def references():
        async with get_pool().acquire() as db:
            rows=await db.fetch('SELECT source,fetched_at,source_date,payload FROM reference_datasets')
        result=[]
        for row in rows:
            payload=json.loads(row['payload']) if isinstance(row['payload'],str) else row['payload']
            result.append({'source':row['source'],'kind':'reference','fetched_at':row['fetched_at'].isoformat(),
              'source_date':row['source_date'],'record_count':payload.get('record_count',len(payload.get('data',payload.get('vulnerabilities',[]))))})
        return {'references':result,'epss_scope':'100 most recently added KEVs; probability of exploitation in next 30 days, not evidence of exploitation'}
