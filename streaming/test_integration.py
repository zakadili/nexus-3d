"""Run inside API image. Uses an isolated temporary schema, never public observations."""
import asyncio
from contextlib import suppress
from contextlib import asynccontextmanager
from datetime import datetime,timezone,timedelta
import json
import logging
from pathlib import Path
import uuid
import asyncpg
import httpx
import app as backend
import operations
import uvicorn
from websockets.asyncio.client import connect
from websockets.exceptions import InvalidStatus

async def main():
    logging.getLogger('httpx').setLevel(logging.WARNING)
    schema='test_'+uuid.uuid4().hex
    admin=await asyncpg.connect(backend.DB)
    await admin.execute(f'CREATE SCHEMA {schema}')
    pool=await asyncpg.create_pool(backend.DB,min_size=1,max_size=2,server_settings={'search_path':schema})
    backend.pool=pool
    try:
        async with pool.acquire() as db:
            await db.execute(Path('schema.sql').read_text())
            await db.execute(operations.SCHEMA)
        now=datetime.now(timezone.utc)
        for _ in range(2):
            await backend.ingest('urlhaus','fixture-private',101,now,'test','test','192.0.2.1',{'test_fixture':True})
        async with pool.acquire() as db:
            assert await db.fetchval('SELECT count(*) FROM observations')==1
            assert await db.fetchval("SELECT last_idx FROM feed_state WHERE feed_source='urlhaus'")==101
        assert await backend.fetch_events()==[], 'Restricted feed leaked'
        await backend.ingest('ioda','fixture-public',None,now,'test','test',None,{'test_fixture':True})
        rows=await backend.fetch_events()
        assert len(rows)==1 and rows[0]['kind']=='observed'
        seq=rows[0]['seq']
        assert await backend.fetch_events(seq)==[]
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=backend.app),base_url='http://test',headers={'X-Real-IP':'isolated-http-test'}) as client:
            r=await client.get('/api/ready'); assert r.status_code==200
            r=await client.get('/api/windows'); assert r.json()['windows'][0]['last_5m']==1
            r=await client.get('/api/events'); assert len(r.json()['events'])==1
            statuses=[(await client.get('/api/ready')).status_code for _ in range(121)]
            assert 429 in statuses
        @asynccontextmanager
        async def isolated_lifespan(app):
            yield
        backend.app.router.lifespan_context=isolated_lifespan
        server=uvicorn.Server(uvicorn.Config(backend.app,host='127.0.0.1',port=8766,log_level='warning'))
        serving=asyncio.create_task(server.serve())
        pump=asyncio.create_task(backend.broadcast_pump())
        try:
            for _ in range(50):
                if server.started: break
                await asyncio.sleep(.1)
            try:
                async with connect('ws://127.0.0.1:8766/ws/live',origin='https://untrusted.invalid'): pass
                raise AssertionError('Untrusted Origin accepted')
            except InvalidStatus as exc: assert exc.response.status_code==403
            async with connect('ws://127.0.0.1:8766/ws/live',origin='https://zakadili.github.io') as ws:
                assert json.loads(await ws.recv())['type']=='health'
                await ws.send(json.dumps({'type':'resume','after_seq':0,'limit':'bad'}))
                message=json.loads(await ws.recv())
                assert message['type']=='replay' and len(message['events'])==1
                await backend.ingest('ioda','fixture-ws',None,now,'test','test',None,{'test_fixture':True})
                message=json.loads(await asyncio.wait_for(ws.recv(),10))
                assert message['type']=='events' and any(e['event_id']=='fixture-ws' for e in message['events'])
            async with connect('ws://127.0.0.1:8766/ws/live',origin='https://zakadili.github.io') as ws:
                await ws.recv()
                await ws.send(json.dumps({'type':'resume','after_seq':seq}))
                message=json.loads(await ws.recv())
                assert any(e['event_id']=='fixture-ws' for e in message['events'])
        finally:
            pump.cancel()
            with suppress(asyncio.CancelledError): await pump
            server.should_exit=True
            await serving
        # Reopen the pool to verify committed events and cursor survive connection loss.
        await pool.close()
        pool=await asyncpg.create_pool(backend.DB,min_size=1,max_size=2,server_settings={'search_path':schema})
        backend.pool=pool
        assert len(await backend.fetch_events())==2
        async with pool.acquire() as db:
            await db.execute('UPDATE observations SET received_at=$1',now-timedelta(days=3))
        task=asyncio.create_task(operations.maintenance(pool,False))
        for _ in range(30):
            async with pool.acquire() as db: count=await db.fetchval('SELECT count(*) FROM observations')
            if count==0: break
            await asyncio.sleep(.1)
        task.cancel()
        with suppress(asyncio.CancelledError): await task
        assert count==0
        assert (await operations.replay_coverage(pool,1,False))['replay_gap']
        await backend.gap('urlhaus',102,110,'test provider retention gap')
        async with pool.acquire() as db:
            assert await db.fetchval("SELECT gap_count FROM feed_state WHERE feed_source='urlhaus'")==1
        print(json.dumps({'passed':['transactional deduplication','durable upstream cursor','restricted feed filtering','event replay','readiness','rolling windows','connection recovery persistence','retention','local replay gap','upstream gap persistence','WebSocket Origin rejection','WebSocket replay','WebSocket broadcast','WebSocket reconnection replay','malformed limit handling','HTTP rate limiting']}))
    finally:
        await pool.close()
        await admin.execute(f'DROP SCHEMA {schema} CASCADE')
        await admin.close()

if __name__=='__main__': asyncio.run(main())
