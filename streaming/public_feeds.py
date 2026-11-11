"""Publishable, globally scoped sources. Polling changes are not observed attacks."""
import asyncio,csv,hashlib,json
from datetime import datetime,timezone
import httpx

SOURCES=[
 {'id':'phishdestroy','name':'PhishDestroy primary','url':'https://raw.githubusercontent.com/phishdestroy/destroylist/main/list.txt','license':'MIT','license_url':'https://github.com/phishdestroy/destroylist/blob/main/LICENSE','format':'lines','cadence':'Published on verification; checked every 5 minutes'},
 {'id':'sslbl_cert','name':'abuse.ch SSLBL certificates','url':'https://sslbl.abuse.ch/blacklist/sslblacklist.csv','license':'CC0','license_url':'https://abuse.ch/terms-of-use/','format':'cert','cadence':'Provider generates every 5 minutes'},
]

def parse(text,fmt):
    rows=[line.strip() for line in text.splitlines() if line.strip() and not line.startswith('#')]
    if fmt=='lines': return sorted(set(x.lower() for x in rows if ' ' not in x and '.' in x and len(x)<254))
    result=[]
    for r in csv.reader(rows):
        if fmt=='cert' and len(r)>=3 and len(r[1].strip())==40: result.append(r[1].strip())
        elif fmt=='ip' and len(r)>=3: result.append(r[1].strip()+':'+r[2].strip())
    return sorted(set(result))

def changes_between(previous,current):
    old,new=set(previous),set(current)
    return [('list_added',v) for v in sorted(new-old)]+[('list_removed',v) for v in sorted(old-new)]

async def collect(pool,health,ingest,gap):
    await health('sslbl_c2','deprecated',degraded='Provider retired this list in January 2025; excluded from current coverage')
    while True:
        for source in SOURCES:
            feed=source['id']
            try:
                async with pool.acquire() as db:
                    old=await db.fetchval('SELECT payload FROM reference_datasets WHERE source=$1','public:'+feed)
                old=json.loads(old) if isinstance(old,str) else old
                headers={}
                if old and old.get('etag'): headers['If-None-Match']=old['etag']
                async with httpx.AsyncClient(timeout=35,follow_redirects=True) as client:
                    async with client.stream('GET',source['url'],headers=headers) as response:
                        if response.status_code==304:
                            async with pool.acquire() as db:
                                await db.execute('UPDATE reference_datasets SET fetched_at=now() WHERE source=$1','public:'+feed)
                            await health(feed,'connected',degraded='Checked unchanged; this does not establish new activity')
                            continue
                        response.raise_for_status()
                        data=bytearray()
                        async for chunk in response.aiter_bytes():
                            data.extend(chunk)
                            if len(data)>16*1024*1024: raise ValueError('Source exceeds 16 MiB safety limit')
                        text=data.decode('utf-8-sig')
                        etag=response.headers.get('etag')
                        modified=response.headers.get('last-modified')
                values=parse(text,source['format'])
                if not values and not (source['format'] in ('cert','ip') and text.lstrip().startswith('#') and 'abuse.ch' in text[:2000]):
                    raise ValueError('Empty/changed source schema; previous baseline preserved')
                if len(values)>300000: raise ValueError('Source exceeds baseline limit')
                generation=hashlib.sha256('\n'.join(values).encode()).hexdigest()
                changes=changes_between(old['values'],values) if old else [('snapshot_baseline',v) for v in values[:20]]
                if len(changes)>1000:
                    await gap(feed,None,None,'Poll contained over 1000 changes; event samples capped, full current baseline retained')
                for action,value in changes[:1000]:
                    uid=feed+':'+hashlib.sha256((generation+action+value).encode()).hexdigest()
                    await ingest(feed,uid,None,None,action,'reported-indicator-list-change',value,{'source_url':source['url'],'license':source['license'],'generation':generation,'kind':'snapshot' if not old else 'observed_list_change'})
                payload={**source,'values':values,'etag':etag,'last_modified':modified,'generation':generation,'record_count':len(values),'sample':values[:20]}
                async with pool.acquire() as db:
                    await db.execute("""INSERT INTO reference_datasets(source,fetched_at,source_date,payload) VALUES($1,now(),$2,$3::jsonb)
                    ON CONFLICT(source) DO UPDATE SET fetched_at=now(),source_date=$2,payload=$3::jsonb""",'public:'+feed,modified,json.dumps(payload))
                await health(feed,'connected',degraded='Polling source; initial entries are snapshots, subsequent differences are list changes, not attacks')
            except asyncio.CancelledError: raise
            except Exception as exc: await health(feed,'degraded',(str(exc) or type(exc).__name__)[:200])
        await asyncio.sleep(300)
