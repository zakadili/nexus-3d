"""NEXUS event ingestion service. One Uvicorn worker. Never invent observed attacks."""
import asyncio, hashlib, ipaddress, json, logging, os, random, re, time
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
from urllib.parse import urlsplit
import asyncpg, httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from websockets.asyncio.client import connect

log=logging.getLogger("nexus")
logging.basicConfig(level=logging.INFO)
DB=os.environ["DATABASE_URL"]
FEEDS=("urlhaus","threatfox","Feodotracker")
IODA="https://api.ioda.inetintel.cc.gatech.edu/v2/outages/alerts"
KEV="https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
ORIGINS=[x.strip() for x in os.getenv("ALLOWED_ORIGINS","https://zakadili.github.io").split(",")]
PUBLIC=os.getenv("PUBLIC_REBROADCAST","false").lower()=="true"
IODA_INTERVAL=max(120,int(os.getenv("IODA_INTERVAL_SECONDS","180")))
KEV_INTERVAL=max(3600,int(os.getenv("KEV_INTERVAL_SECONDS","86400")))
pool=None
listeners=set()
tasks=[]
broadcast=asyncio.Queue(maxsize=10000)

def timestamp(value):
    if isinstance(value,(float,int)):
        return datetime.fromtimestamp(value,timezone.utc)
    if isinstance(value,str):
        with suppress(ValueError):
            return datetime.fromisoformat(value.replace("Z","+00:00")).astimezone(timezone.utc)
    return None

def ip_literal(value):
    if not isinstance(value,str): return None
    try:
        v=urlsplit(value).hostname if "://" in value else value
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}:\d+",v):
            v=v.rsplit(":",1)[0]
        return str(ipaddress.ip_address(v))
    except (ValueError,TypeError): return None

async def health(feed,state,error=None,degraded=None):
    async with pool.acquire() as db:
        await db.execute("""INSERT INTO feed_state(feed_source,state,last_attempt_at,last_error,degraded_reason)
          VALUES($1,$2,now(),$3,$4) ON CONFLICT(feed_source) DO UPDATE
          SET state=$2,last_attempt_at=now(),last_error=$3,degraded_reason=$4,
          last_success_at=CASE WHEN $2 IN ('connected','reference_current') THEN now() ELSE feed_state.last_success_at END""",
          feed,state,error,degraded)

async def cursor(feed):
    async with pool.acquire() as db:
        return await db.fetchval("SELECT last_idx FROM feed_state WHERE feed_source=$1",feed)

async def gap(feed,first,last,reason):
    async with pool.acquire() as db:
        async with db.transaction():
            await db.execute("INSERT INTO coverage_gaps(feed_source,first_idx,last_idx,reason) VALUES($1,$2,$3,$4)",feed,first,last,reason)
            await db.execute("INSERT INTO feed_state(feed_source,state,gap_count,degraded_reason) VALUES($1,'degraded',1,$2) ON CONFLICT(feed_source) DO UPDATE SET state='degraded',gap_count=feed_state.gap_count+1,degraded_reason=$2",feed,reason)

async def ingest(feed,uid,idx,source_ts,action,threat,indicator,raw):
    """Observation and source cursor are committed in one DB transaction."""
    indicator=str(indicator)[:2048] if indicator is not None else None
    ip=ip_literal(indicator)
    async with pool.acquire() as db:
        async with db.transaction():
            row=await db.fetchrow("""INSERT INTO observations(event_id,feed_source,upstream_idx,source_ts,action,threat_type,indicator,indicator_ip,raw_payload)
              VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb) ON CONFLICT DO NOTHING
              RETURNING seq,received_at""",uid,feed,idx,source_ts,action,threat,indicator,ip,json.dumps(raw))
            await db.execute("""INSERT INTO feed_state(feed_source,state,last_idx,last_event_at,last_received_at,last_success_at)
              VALUES($1,'connected',$2,$3,now(),now())
              ON CONFLICT(feed_source) DO UPDATE SET
              state='connected',
              last_idx=CASE WHEN EXCLUDED.last_idx IS NULL THEN feed_state.last_idx ELSE GREATEST(feed_state.last_idx,EXCLUDED.last_idx) END,
              last_event_at=$3,last_received_at=now(),last_success_at=now(),
              last_error=NULL""",feed,idx,source_ts)
    if row and (PUBLIC or feed not in FEEDS):
        event=dict(seq=row["seq"],event_id=uid,feed_source=feed,kind="observed",action=action,
                   threat_type=threat,indicator=indicator,indicator_ip=ip,
                   source_ts=source_ts.isoformat() if source_ts else None,received_at=row["received_at"].isoformat(),
                   country_code=None,asn=None,enrichment_source=None,assessment=None,
                   upstream_idx=str(idx) if idx is not None else None)
        try: broadcast.put_nowait(event)
        except asyncio.QueueFull: log.error("Broadcast queue full: replay remains durable")

async def auth_token():
    if os.getenv("SPAMHAUS_TOKEN"): return os.environ["SPAMHAUS_TOKEN"]
    user,pw=os.getenv("SPAMHAUS_USER"),os.getenv("SPAMHAUS_PASSWORD")
    if not user or not pw: raise RuntimeError("Spamhaus credentials missing")
    async with httpx.AsyncClient(timeout=20) as c:
        r=await c.post("https://api.spamhaus.org/api/v1/login",json={"username":user,"password":pw,"realm":"abusert"})
        r.raise_for_status()
        return r.json()["token"]

async def upstream(feed):
    backoff=1
    while True:
        try:
            token=await auth_token()
            await health(feed,"connecting")
            async with connect("wss://rt.spamhaus.net/streams/v1/abuse.ch/"+feed,
                    additional_headers={"Authorization":"Bearer "+token},
                    ping_interval=20,ping_timeout=20,open_timeout=20) as ws:
                await ws.send("status")
                status=await asyncio.wait_for(ws.recv(),timeout=15)
                m=re.fullmatch(r"status\s+(\d+)\s+(\d+)",str(status).strip())
                if not m: raise RuntimeError("Unrecognized status response: "+str(status)[:150])
                oldest,newest=map(int,m.groups())
                last=await cursor(feed)
                if last is None: command="start"
                elif int(last)+1<oldest:
                    await gap(feed,int(last)+1,oldest-1,"Upstream cursor expired; missing messages cannot be recovered")
                    command=f"resume {oldest}"
                elif int(last)<newest: command=f"resume {int(last)+1}"
                else: command="start"
                await ws.send(command)
                await health(feed,"connected")
                backoff=1
                async for message in ws:
                    try:
                        data=json.loads(message)
                        if not isinstance(data,dict) or "_idx" not in data: continue
                        idx=int(data["_idx"])
                        indicator=data.get("ioc") or data.get("url") or data.get("host") or data.get("ip")
                        # Never relabel a feed mention as an attack seen by the site.
                        await ingest(feed,f"{feed}:{idx}",idx,timestamp(data.get("_ts")),
                            str(data.get("type") or "feed_update"),
                            {"urlhaus":"malware-url-report","threatfox":"ioc-report","Feodotracker":"c2-report"}[feed],
                            indicator,data)
                    except Exception:
                        log.exception("Malformed %s message (not acknowledged)",feed)
                        raise
        except asyncio.CancelledError: raise
        except Exception as exc:
            log.warning("%s connection failed: %s",feed,exc)
            await health(feed,"disconnected",str(exc)[:300])
            await asyncio.sleep(min(backoff,300)+random.random()*3)
            backoff=min(backoff*2,300)

async def collect_ioda():
    while True:
        try:
            await health("ioda","connecting")
            async with httpx.AsyncClient(timeout=30) as client:
                now=int(time.time())
                r=await client.get(IODA,params={"from":now-900,"until":now,"limit":1000,"page":0})
                if r.status_code==429:
                    await health("ioda","degraded","Rate limited","Backoff required")
                    delay=int(r.headers.get("Retry-After","180"))
                    await asyncio.sleep(max(30,min(delay,3600)))
                    continue
                r.raise_for_status()
                payload=r.json()
            entries=payload.get("data",[]) if isinstance(payload,dict) else payload
            if not isinstance(entries,list): raise ValueError("IODA response schema changed")
            if len(entries)>=1000:
                await health("ioda","degraded",degraded="Response cap reached; pagination required, coverage not complete")
            else: await health("ioda","connected")
            for item in entries:
                if not isinstance(item,dict): continue
                ent=item.get("entity") or {}
                key=json.dumps(item,sort_keys=True,default=str)
                uid="ioda:"+hashlib.sha256(key.encode()).hexdigest()
                await ingest("ioda",uid,None,timestamp(item.get("time") or item.get("start")),
                    "connectivity_alert","internet-disruption-observation",
                    ent.get("code") if isinstance(ent,dict) else None,item)
        except asyncio.CancelledError: raise
        except Exception as exc:
            await health("ioda","degraded",str(exc)[:300])
            log.warning("IODA: %s",exc)
        await asyncio.sleep(IODA_INTERVAL)

async def collect_kev():
    while True:
        try:
            await health("cisa_kev","connecting")
            async with httpx.AsyncClient(timeout=35) as client:
                r=await client.get(KEV)
                r.raise_for_status()
                data=r.json()
            if not isinstance(data.get("vulnerabilities"),list): raise ValueError("Invalid KEV catalog")
            async with pool.acquire() as db:
                await db.execute("""INSERT INTO reference_datasets(source,fetched_at,source_date,payload)
                   VALUES('cisa_kev',now(),$1,$2::jsonb)
                   ON CONFLICT(source) DO UPDATE SET fetched_at=now(),source_date=$1,payload=$2::jsonb""",
                   data.get("dateReleased"),json.dumps(data))
            await health("cisa_kev","reference_current")
        except asyncio.CancelledError: raise
        except Exception as exc: await health("cisa_kev","degraded",str(exc)[:300])
        await asyncio.sleep(KEV_INTERVAL)

def serialize(row):
    d=dict(row)
    for k,v in list(d.items()):
        if isinstance(v,datetime): d[k]=v.isoformat()
        elif isinstance(v,(ipaddress.IPv4Address,ipaddress.IPv6Address)): d[k]=str(v)
        elif k=="upstream_idx" and v is not None: d[k]=str(v)
    return d

async def fetch_events(after=0,limit=300,feed=None):
    async with pool.acquire() as db:
        q="""SELECT seq,event_id,feed_source,upstream_idx,source_ts,received_at,action,threat_type,
            indicator,indicator_ip,country_code,asn,enrichment_source,assessment
            FROM observations WHERE seq>$1 AND ($3::text IS NULL OR feed_source=$3)
            AND ($4::boolean OR feed_source NOT IN ('urlhaus','threatfox','Feodotracker'))
            ORDER BY seq LIMIT $2"""
        rows=await db.fetch(q,after,limit,feed,PUBLIC)
        return [dict(serialize(r),kind="observed") for r in rows]

async def snapshot_health():
    async with pool.acquire() as db:
        rows=await db.fetch("""SELECT feed_source,state,last_idx,last_event_at,last_received_at,last_success_at,
             last_attempt_at,last_error,gap_count,degraded_reason FROM feed_state ORDER BY feed_source""")
    return [{"feed":r["feed_source"],"state":r["state"],"last_idx":str(r["last_idx"]) if r["last_idx"] is not None else None,
             "last_event_at":r["last_event_at"].isoformat() if r["last_event_at"] else None,
             "last_received_at":r["last_received_at"].isoformat() if r["last_received_at"] else None,
             "last_success_at":r["last_success_at"].isoformat() if r["last_success_at"] else None,
             "gap_count":r["gap_count"],"degraded_reason":r["degraded_reason"] or r["last_error"],
             "source_to_ingest_latency_s":round((r["last_received_at"]-r["last_event_at"]).total_seconds(),2) if r["last_received_at"] and r["last_event_at"] else None,
             "last_success_age_s":round((datetime.now(timezone.utc)-r["last_success_at"]).total_seconds(),1) if r["last_success_at"] else None} for r in rows]

async def broadcast_pump():
    while True:
        first=await broadcast.get()
        await asyncio.sleep(2)
        batch=[first]
        while not broadcast.empty() and len(batch)<300: batch.append(broadcast.get_nowait())
        dead=[]
        for client in tuple(listeners):
            try: await asyncio.wait_for(client.send_json({"type":"events","events":batch}),timeout=3)
            except Exception: dead.append(client)
        for client in dead:
            listeners.discard(client)
            with suppress(Exception): await client.close()

@asynccontextmanager
async def lifespan(app):
    global pool
    pool=await asyncpg.create_pool(DB,min_size=1,max_size=8)
    for feed in (*FEEDS,"ioda","cisa_kev"): await health(feed,"initializing")
    tasks.extend([asyncio.create_task(upstream(f)) for f in FEEDS])
    tasks.extend([asyncio.create_task(collect_ioda()),asyncio.create_task(collect_kev()),asyncio.create_task(broadcast_pump())])
    try: yield
    finally:
        for task in tasks: task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        await pool.close()

app=FastAPI(title="NEXUS streaming intelligence",lifespan=lifespan)
app.add_middleware(CORSMiddleware,allow_origins=ORIGINS,allow_methods=["GET"],allow_headers=["*"])

@app.get("/api/health")
async def api_health():
    return {"feeds":await snapshot_health(),"public_feed_rebroadcast":PUBLIC,
            "disclaimer":"Feed records are not attacks observed by NEXUS. No arrival does not imply zero activity."}

@app.get("/api/events")
async def api_events(after:int=0,limit:int=300):
    events=await fetch_events(max(0,after),min(max(1,limit),500))
    return {"events":events,"next_after_seq":events[-1]["seq"] if events else after,
            "has_more":len(events)>=min(max(1,limit),500)}

@app.get("/api/windows")
async def api_windows():
    async with pool.acquire() as db:
        rows=await db.fetch("""SELECT feed_source,
          COUNT(*) FILTER(WHERE received_at>now()-interval '5 minutes') AS last_5m,
          COUNT(*) FILTER(WHERE received_at>now()-interval '15 minutes') AS last_15m,
          COUNT(*) FILTER(WHERE received_at>now()-interval '60 minutes') AS last_60m
          FROM observations WHERE received_at>now()-interval '60 minutes'
          AND ($1::boolean OR feed_source NOT IN ('urlhaus','threatfox','Feodotracker'))
          GROUP BY feed_source""",PUBLIC)
    return {"windows":[dict(r) for r in rows],"measure":"feed record arrivals, not attacks"}

@app.websocket("/ws/live")
async def socket(ws:WebSocket):
    if ws.headers.get("origin") not in ORIGINS:
        await ws.close(code=1008)
        return
    await ws.accept()
    listeners.add(ws)
    try:
        await ws.send_json({"type":"health",**(await api_health())})
        while True:
            try: msg=await asyncio.wait_for(ws.receive_json(),timeout=15)
            except asyncio.TimeoutError:
                await ws.send_json({"type":"health",**(await api_health())})
                continue
            if msg.get("type")=="resume":
                after=msg.get("after_seq",0)
                if type(after)!=int or after<0: after=0
                ev=await fetch_events(after,min(max(1,int(msg.get("limit",300))),500))
                await ws.send_json({"type":"replay","events":ev,
                    "next_after_seq":ev[-1]["seq"] if ev else after,
                    "has_more":len(ev)>=min(max(1,int(msg.get("limit",300))),500)})
            elif msg.get("type")=="upstream_cursor":
                feed=msg.get("feed")
                idx=msg.get("idx")
                if feed not in FEEDS or not str(idx).isdigit():
                    await ws.send_json({"type":"error","message":"Invalid cursor or feed"})
                    continue
                if not PUBLIC:
                    await ws.send_json({"type":"error","message":"Upstream replay restricted by redistribution policy"})
                    continue
                async with pool.acquire() as db:
                    rows=await db.fetch("""SELECT seq,event_id,feed_source,upstream_idx,source_ts,received_at,
                         action,threat_type,indicator,indicator_ip,country_code,asn,enrichment_source,assessment
                         FROM observations WHERE feed_source=$1 AND upstream_idx>$2 ORDER BY upstream_idx LIMIT 300""",
                         feed,int(idx))
                await ws.send_json({"type":"upstream_replay","events":[dict(serialize(r),kind="observed") for r in rows]})
    except (WebSocketDisconnect,RuntimeError): pass
    finally: listeners.discard(ws)
