#!/usr/bin/env python3
"""NEXUS multi-source intelligence snapshot builder (stdlib only).
Data is observational. No external IP is scanned. An IP on a list is not an actor.
Data providers remain separately labeled; counts must not be interpreted as incidents.
"""
from bisect import bisect_right
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import csv
import gzip
import io
import ipaddress
import json
from pathlib import Path
import re
import time
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor

ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT / "data" / "overview.json"
SOURCE_FEEDS={
 "blocklistde":("blocklist.de","https://lists.blocklist.de/lists/all.txt","IP addresses reported in recent 48-hour attacks against participating systems"),
 "ipsum":("IPsum (3+ lists)","https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt","Addresses appearing on 3+ constituent IPsum source lists; NOT confirmed attackers"),
 "dshield":("SANS ISC / DShield","https://isc.sans.edu/api/topips/records/300?json","Top sensor-observed source IP addresses; includes benign scanners"),
 "feodo":("abuse.ch Feodo Tracker","https://feodotracker.abuse.ch/downloads/ipblocklist.json","Active botnet C2 indicators; feed can be empty following takedowns"),
}
CISA="https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
EPSS="https://api.first.org/data/v1/epss?cve="
NVD="https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
GEO="https://github.com/sapics/ip-location-db/releases/download/latest/user-country-ipv4.csv"
USER_AGENT="NEXUS-Sentinel-Research/0.2 (https://github.com/zakadili/nexus-3d; contact via issues)"
MAX_BYTES=25_000_000

def fetch(url, cap=MAX_BYTES, timeout=40):
    req=Request(url,headers={"User-Agent":USER_AGENT,"Accept":"application/json,text/plain,*/*"})
    with urlopen(req,timeout=timeout) as r:
        raw=r.read(cap+1)
        if len(raw)>cap:raise ValueError("download exceeds source limit")
        return raw

def get_json(url,cap=MAX_BYTES,timeout=40):
    return json.loads(fetch(url,cap,timeout))

def global_v4(value):
    try:
        ip=ipaddress.ip_address(str(value).strip())
        return str(ip) if ip.version==4 and ip.is_global else None
    except ValueError:return None

def dshield_rows(document):
    if isinstance(document,list):rows=document
    elif isinstance(document,dict):
        rows=document.get("ipaddress") or document.get("topips") or document.get("data")
        if isinstance(rows,dict):rows=list(rows.values())
        if not isinstance(rows,list):rows=[val for key,val in document.items() if str(key).isdigit() and isinstance(val,dict)]
    else:rows=[]
    out=[]
    for row in rows or []:
        if not isinstance(row,dict):continue
        ip=global_v4(row.get("source") or row.get("ip") or row.get("ipaddress"))
        if ip:
            try:
                reports=max(0,int(row.get("reports",0) or 0))
                targets=max(0,int(row.get("targets",0) or 0))
            except (TypeError,ValueError):
                reports=targets=0
            out.append({"ip":ip,"reports":reports,"targets":targets})
    return out

def get_feed(key):
    label,url,meaning=SOURCE_FEEDS[key]
    try:
        raw=fetch(url)
        if key=="dshield":
            parsed=dshield_rows(json.loads(raw));ips={r["ip"] for r in parsed}
            return key,ips,{"id":key,"name":label,"status":"ok","records":len(ips),"meaning":meaning,"url":url},parsed[:80]
        if key=="feodo":
            parsed=json.loads(raw)
            if isinstance(parsed,dict) and isinstance(parsed.get("data"),list):
                parsed=parsed["data"]
            if not isinstance(parsed,list):raise ValueError("unexpected Feodo JSON")
            ips={ip for row in parsed if isinstance(row,dict) and row.get("status")=="online" if (ip:=global_v4(row.get("ip_address")))}
        else:
            ips=set()
            for line in raw.decode("utf-8-sig",errors="replace").splitlines():
                line=line.strip()
                if not line or line.startswith("#"):continue
                ip=global_v4(line.split()[0])
                if ip:ips.add(ip)
        return key,ips,{"id":key,"name":label,"status":"ok","records":len(ips),"meaning":meaning,"url":url},[]
    except Exception as exc:
        return key,set(),{"id":key,"name":label,"status":"unavailable","records":None,"meaning":meaning,"url":url,"error":str(exc)[:180]},[]

class GeoDB:
    def __init__(self,rows):
        self.starts=[];self.ends=[];self.codes=[]
        for row in rows:
            if len(row)<3:continue
            try:
                a=int(ipaddress.IPv4Address(row[0]));b=int(ipaddress.IPv4Address(row[1]))
            except (ValueError,ipaddress.AddressValueError):continue
            if a>b:continue
            self.starts.append(a);self.ends.append(b);self.codes.append(row[2].upper())
        ordered=sorted(zip(self.starts,self.ends,self.codes))
        self.starts=[x[0] for x in ordered];self.ends=[x[1] for x in ordered];self.codes=[x[2] for x in ordered]
    def locate(self,ip):
        n=int(ipaddress.IPv4Address(ip));i=bisect_right(self.starts,n)-1
        if i>=0 and n<=self.ends[i] and re.fullmatch("[A-Z]{2}",self.codes[i]):return self.codes[i]
        return None

def geo_db():
    raw=fetch(GEO,cap=35_000_000,timeout=100)
    # Country CSV has start IPv4,end IPv4,country code; no personal location.
    return GeoDB(csv.reader(io.StringIO(raw.decode("utf-8-sig"))))

def collect_indicators():
    with ThreadPoolExecutor(max_workers=4) as pool:
        results=list(pool.map(get_feed,SOURCE_FEEDS))
    available=[x for x in results if x[2]["status"]=="ok"]
    if not available:raise RuntimeError("All IP intelligence sources unavailable")
    geodb=geo_db()
    by_ip=defaultdict(set)
    for key,ips,meta,rows in available:
        for ip in ips:by_ip[ip].add(key)
    countries=defaultdict(lambda:{"total":0,"by_source":Counter(),"examples":[],"samples_by_source":defaultdict(list),"multi_source_count":0})
    unresolved=0
    # Deterministic evidence samples: at most five IPs per provider/country, plus up to
    # three overlapping IPs. The samples are NOT severity-ranked or comprehensive.
    for ip,origins in sorted(by_ip.items(),key=lambda item:int(ipaddress.IPv4Address(item[0]))):
        code=geodb.locate(ip)
        if not code:unresolved+=1;continue
        c=countries[code];c["total"]+=1
        if len(origins)>1:
            c["multi_source_count"]+=1
            if len(c["examples"])<3:c["examples"].append({"ip":ip,"sources":sorted(origins)})
        for origin in sorted(origins):
            c["by_source"][origin]+=1
            if len(c["samples_by_source"][origin])<5:
                c["samples_by_source"][origin].append({"ip":ip,"sources":sorted(origins)})
    records=[{"code":code,"indicators":row["total"],"by_source":dict(row["by_source"]),
              "multi_source_count":row["multi_source_count"],
              "samples_by_source":dict(row["samples_by_source"]),
              "examples":row["examples"]} for code,row in countries.items()]
    records.sort(key=lambda x:(-x["indicators"],x["code"]))
    dshield=next((r for _,_,_,rows in available for r in [rows] if rows),[])
    return {
        "unique_indicators":len(by_ip),"resolved_indicators":len(by_ip)-unresolved,
        "unresolved_indicators":unresolved,
        "countries":records,"source_health":[r[2] for r in results],
        "dshield_sample":dshield,
        "geo_method":"DB-IP Lite Country via sapics/ip-location-db, CC BY 4.0, approximate IP allocation; not attacker attribution",
        "geo_url":"https://db-ip.com/"
    }

def chunks(values,n):
    for i in range(0,len(values),n):yield values[i:i+n]

def get_epss(ids):
    scores={}
    for batch in chunks(ids,65):
        try:
            data=get_json(EPSS+quote(",".join(batch),safe=","))
            for row in data.get("data",[]):
                try:scores[row["cve"]]={"epss":float(row["epss"]),"percentile":float(row["percentile"])}
                except (KeyError,ValueError,TypeError):continue
        except Exception:pass
        time.sleep(.3)
    return scores

def nvd_score(cve):
    try:
        doc=get_json(NVD+quote(cve),cap=2_000_000,timeout=17)
        for vulnerability in doc.get("vulnerabilities",[]):
            metrics=vulnerability.get("cve",{}).get("metrics",{})
            for key in ("cvssMetricV40","cvssMetricV31","cvssMetricV30","cvssMetricV2"):
                scores=metrics.get(key) or []
                if scores:
                    data=scores[0].get("cvssData",{})
                    return {"score":data.get("baseScore"),"severity":data.get("baseSeverity"),"version":data.get("version")}
    except Exception:pass
    return None

def collect_cves():
    try:
        doc=get_json(CISA)
        vulns=doc.get("vulnerabilities",[])
        if not isinstance(vulns,list) or not vulns:raise ValueError("bad CISA KEV format")
        vulns=[v for v in vulns if isinstance(v,dict)]
        if not vulns:raise ValueError("no valid KEV records")
    except Exception as exc:
        return {"status":"unavailable","error":str(exc)[:170],"source":CISA}
    now=datetime.now(timezone.utc).date()
    def cve_date(v):
        try:return datetime.strptime(v["dateAdded"],"%Y-%m-%d").date()
        except (KeyError,TypeError,ValueError):return datetime(1970,1,1).date()
    latest=sorted(vulns,key=cve_date,reverse=True)
    selection={v["cveID"]:v for v in latest[:300] if isinstance(v.get("cveID"),str) and re.fullmatch(r"CVE-\d{4}-\d{4,}",v["cveID"])}
    for v in latest:
        if v.get("knownRansomwareCampaignUse")=="Known" and len(selection)<550 and isinstance(v.get("cveID"),str) and re.fullmatch(r"CVE-\\d{4}-\\d{4,}",v["cveID"]):selection[v["cveID"]]=v
    epss=get_epss(list(selection))
    ranked=[]
    for v in selection.values():
        score=epss.get(v["cveID"],{})
        days=max(0,(now-cve_date(v)).days)
        ransomware=v.get("knownRansomwareCampaignUse")=="Known"
        # Prioritization score is a heuristic, not a severity standard.
        priority=round((float(score.get("epss",0))*100)+(25 if ransomware else 0)+(10 if days<=30 else 0),2)
        ranked.append({
            "id":v["cveID"],"vendor":v.get("vendorProject"),"product":v.get("product"),
            "name":v.get("vulnerabilityName"),"description":v.get("shortDescription"),
            "date_added":v.get("dateAdded"),"due_date":v.get("dueDate"),
            "ransomware_observed":ransomware,"epss":score.get("epss"),"epss_percentile":score.get("percentile"),
            "priority":priority
        })
    ranked.sort(key=lambda x:(-x["priority"],x["id"]))
    # CVSS enrichment is intentionally limited to avoid abusing NVD's public rate limits.
    for v in ranked[:3]:
        v["cvss"]=nvd_score(v["id"])
        time.sleep(6.5)
    return {"status":"ok","source":CISA,"total_kev":len(vulns),
            "catalog_version":doc.get("catalogVersion"),"date_released":doc.get("dateReleased"),
            "epss_source":"https://www.first.org/epss/","scored_candidates":len(ranked),
            "ranking_method":"Heuristic: EPSS probability x100 + 25 if known ransomware use + 10 if added within 30 days; ONLY CISA KEV candidates. Not a CVSS or asset-specific risk score.",
            "top":ranked[:35]}

def compact_snapshot(snapshot):
    """Country-level indicators only; preserves trends without republishing IP lists."""
    indicators=snapshot.get("indicators") or {}
    countries=indicators.get("countries") or []
    if not countries or indicators.get("unique_indicators") is None:
        return None
    health=indicators.get("source_health") or []
    return {
        "generated_at": snapshot.get("generated_at"),
        "unique_indicators": indicators.get("unique_indicators"),
        "available_sources": sorted(row["id"] for row in health if row.get("status")=="ok"),
        "country_counts": {r["code"]:r["indicators"] for r in countries}
    }


def assemble_history(new_snapshot, previous=None, limit=28):
    """Retain at most 28 real samples (about one week at six-hour cadence)."""
    entries=list((previous or {}).get("history") or [])
    if previous and not entries:
        old=compact_snapshot(previous)
        if old:entries.append(old)
    latest=compact_snapshot(new_snapshot)
    if latest and (not entries or entries[-1].get("generated_at")!=latest["generated_at"]):
        entries.append(latest)
    return entries[-limit:]


def _country_research_sample(row, limit=3):
    """Select a few public source IPs across providers, without address scanning."""
    by_source=row.get("samples_by_source") or {}
    keys=("blocklistde","ipsum","dshield","feodo")
    ordered=[];seen=set()
    for i in range(5):
        for key in keys:
            entries=by_source.get(key) or []
            if i>=len(entries):
                continue
            ip=global_v4(entries[i].get("ip"))
            if ip and ip not in seen:
                seen.add(ip);ordered.append(ip)
                if len(ordered)>=limit:
                    return ordered
    return ordered


def _internetdb_ip(ip):
    """Read Shodan's public, weekly-updated InternetDB metadata (no port scans)."""
    url="https://internetdb.shodan.io/"+quote(ip)
    try:
        d=get_json(url,cap=150_000,timeout=9)
        return {"ip":ip,"status":"ok",
                "vulns":[c for c in d.get("vulns",[]) if isinstance(c,str) and re.fullmatch(r"CVE-\\d{4}-\\d{4,}",c)][:100],
                "ports":[p for p in d.get("ports",[]) if isinstance(p,int) and 0<p<=65535][:100]}
    except HTTPError as exc:
        if exc.code==404:
            return {"ip":ip,"status":"not_indexed","vulns":[],"ports":[]}
        return {"ip":ip,"status":"unavailable"}
    except Exception:
        return {"ip":ip,"status":"unavailable"}


def collect_country_cve_samples(indicators, previous):
    """Optional country research, once daily. Not a nationwide CVE prevalence claim."""
    if not indicators.get("countries"):
        return {"status":"unavailable","reason":"Country indicator dataset unavailable"}
    old=(previous or {}).get("country_cve_signals") or {}
    try:
        age=(datetime.now(timezone.utc)-datetime.fromisoformat(old.get("collected_at",""))).total_seconds()
        if old.get("status")=="ok" and 0<=age<24*3600:
            return old
    except (ValueError,TypeError):
        pass
    selected={}
    all_ips=set()
    for row in indicators["countries"]:
        sample=_country_research_sample(row,3)
        if sample:
            selected[row["code"]]=sample
            all_ips.update(sample)
    if not all_ips:
        return {"status":"unavailable","reason":"No eligible sample IPs"}
    with ThreadPoolExecutor(max_workers=6) as pool:
        result=list(pool.map(_internetdb_ip,sorted(all_ips)))
    by_ip={entry["ip"]:entry for entry in result}
    countries={}
    successes=0
    for code,ips in selected.items():
        records=[by_ip[ip] for ip in ips]
        hits=[r for r in records if r["status"]=="ok"]
        successes+=len(hits)
        cves=Counter(cve for r in hits for cve in set(r["vulns"]))
        ports=Counter(port for r in hits for port in set(r["ports"]))
        countries[code]={
            "requested":len(records),
            "responded":len(hits),
            "unindexed":sum(r["status"]=="not_indexed" for r in records),
            "failed":sum(r["status"]=="unavailable" for r in records),
            "with_cves":sum(bool(r["vulns"]) for r in hits),
            "cves":[{"id":id,"sample_ips":n} for id,n in sorted(cves.items(),key=lambda x:(-x[1],x[0]))[:10]],
            "ports":[{"port":p,"sample_ips":n} for p,n in sorted(ports.items(),key=lambda x:(-x[1],x[0]))[:10]]
        }
    return {
        "status":"ok" if successes else "unavailable",
        "source":"Shodan InternetDB",
        "source_url":"https://book.shodan.io/developer-apis/internetdb/",
        "collected_at":datetime.now(timezone.utc).isoformat(),
        "requested_ips":len(all_ips),
        "responded_ips":successes,
        "meaning":"Weekly-updated passive metadata for <=3 nonrandom, provider-list sample IPs per country; vulns include unverified entries. NOT country CVE prevalence or confirmed exploitation.",
        "countries":countries
    }


def main():
    generated=datetime.now(timezone.utc).isoformat()
    failures=[]
    try:indicators=collect_indicators()
    except Exception as exc:indicators={"status":"unavailable","countries":[],"unique_indicators":None,"source_health":[],"error":str(exc)[:200]};failures.append("indicators")
    cves=collect_cves()
    if cves.get("status")!="ok":failures.append("cves")
    # ENISA ETL 2026: January–December 2025 EU observed incidents, NOT real-time world stats.
    sectors={"source":"ENISA Threat Landscape 2026","source_url":"https://www.enisa.europa.eu/topics/cyber-threats/threat-landscape",
             "report_published":"2026-09-22","period":"2025-01-01 / 2025-12-31","scope":"EU incidents curated by ENISA",
             "note":"Sector share of recorded 2025 incidents (rounded by ENISA); not live, not worldwide, not sector exposure prevalence.",
             "rows":[{"name":"Public administration","percent":31.8},{"name":"Business services","percent":8.5},
                     {"name":"Transport","percent":8.0},{"name":"Manufacturing","percent":6.9},{"name":"Finance / banking","percent":5.6}]}
    output={"schema":2,"generated_at":generated,"data_lag":"Feeds update on different schedules; this is a collection snapshot, not live packet streaming.",
            "indicators":indicators,"cves":cves,"sectors":sectors,"failures":failures}
    if "indicators" in failures:raise RuntimeError("No usable IP feeds; refusing to overwrite last valid country snapshot")
    previous=None
    try:
        if OUT.exists():
            previous=json.loads(OUT.read_text(encoding="utf-8"))
    except (OSError,ValueError):
        previous=None
    output["history"]=assemble_history(output,previous)
    try:
        output["country_cve_signals"]=collect_country_cve_samples(indicators,previous)
    except Exception as exc:
        output["country_cve_signals"]={"status":"unavailable","reason":str(exc)[:180]}
    OUT.parent.mkdir(exist_ok=True,parents=True)
    OUT.write_text(json.dumps(output,indent=2)+"\n",encoding="utf-8")
    print("Published:",OUT,"countries:",len(indicators["countries"]),"KEV:",cves.get("total_kev"),"failures:",failures)

if __name__=="__main__":main()
