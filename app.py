# -*- coding: utf-8 -*-
from flask import Flask, jsonify, render_template_string, request
from enum import IntEnum
import subprocess, json, hashlib, socket, ipaddress, threading, argparse, os, sys
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)

HTML = r"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Windows 11 Route Table Monitor</title>
<style>
*{box-sizing:border-box}
html,body{height:100%;margin:0;font-family:"Segoe UI",Arial,sans-serif;background:#f5f7fa;color:#172033}
body{display:flex;flex-direction:column;overflow:hidden}
.header{background:#fff;border-bottom:1px solid #d8dee8;padding:10px 14px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.title{font-size:18px;font-weight:700;margin-right:8px}
select,input,button{height:34px;border:1px solid #cbd3df;border-radius:6px;background:#fff;padding:0 9px;font:inherit}
input[type=text]{width:310px}
button{cursor:pointer}
button:hover{background:#f1f4f8}
.auto{display:flex;align-items:center;gap:5px;font-size:13px}
.status{margin-left:auto;font-size:12px;color:#667085}
.wrap{flex:1;min-height:0;display:flex;flex-direction:column}
.table-wrap{flex:1;min-height:0;overflow:auto;background:#fff}
table{border-collapse:separate;border-spacing:0;min-width:2350px;width:100%;font-size:12px}
th{position:sticky;top:0;z-index:5;background:#eef2f6;color:#344054;font-weight:700;text-align:left;border-bottom:1px solid #cfd6df;border-right:1px solid #dce1e8;padding:8px 7px;white-space:nowrap}
td{border-bottom:1px solid #edf0f4;border-right:1px solid #f0f2f5;padding:7px;white-space:nowrap;vertical-align:middle}
tbody tr:hover{background:#f5f9ff}
.default{font-weight:700;background:#fff9f9}
.badge{display:inline-block;padding:2px 6px;border-radius:10px;background:#eef2f6;font-size:11px}
.active{background:#dcfce7;color:#166534}
.inactive{background:#fee2e2;color:#991b1b}
.dns{color:#175cd3}
.muted{color:#98a2b3}
.footer{height:38px;background:#fff;border-top:1px solid #d8dee8;display:flex;align-items:center;gap:22px;padding:0 12px;font-size:12px;color:#667085}
.footer b{color:#172033}
#loading{color:#175cd3}
</style>
</head>
<body>
<div class="header">
  <div class="title">Windows 11 Route Table</div>
  <select id="family"><option>IPv4</option><option>IPv6</option></select>
  <input id="search" type="text" placeholder="Hedef, DNS, gateway, arayüz, protokol...">
  <button id="refresh">Yenile</button>
  <label class="auto"><input id="auto" type="checkbox" checked> Otomatik</label>
  <select id="interval" style="width:75px"><option>2</option><option selected>5</option><option>10</option><option>30</option><option>60</option></select>
  <button id="dnsBtn">DNS'leri yenile</button>
  <div id="status" class="status">Hazırlanıyor...</div>
</div>

<div class="wrap">
<div class="table-wrap">
<table>
<thead>
<tr>
<th>Hedef Prefix</th>
<th>Hedef DNS (PTR)</th>
<th>Next Hop</th>
<th>Next Hop DNS</th>
<th>Arayüz</th>
<th>Index</th>
<th>Route Metric</th>
<th>Interface Metric</th>
<th>Protocol</th>
<th>State</th>
<th>Type</th>
<th>Origin</th>
<th>Valid Lifetime</th>
<th>Preferred Lifetime</th>
<th>Policy Store</th>
<th>Compartment ID</th>
<th>Publish</th>
<th>Store</th>
</tr>
</thead>
<tbody id="rows"></tbody>
</table>
</div>
<div class="footer">
<span>Route: <b id="count">0</b></span>
<span>Arayüz: <b id="ifcount">0</b></span>
<span>Gateway: <b id="gwcount">0</b></span>
<span>DNS çözülen: <b id="dnscount">0</b></span>
<span id="loading"></span>
</div>
</div>

<script>
let routes=[],lastHash="",timer=null;
const $=id=>document.getElementById(id);

function esc(v){
 return String(v??"").replace(/[&<>"']/g,m=>({
 "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"
 }[m]));
}
function val(v){return v===null||v===undefined||v===""?"-":v}
function dns(v){return v?`<span class="dns">${esc(v)}</span>`:'<span class="muted">-</span>'}

function render(){
 const q=$("search").value.trim().toLowerCase();
 const body=$("rows");
 body.innerHTML="";
 const filtered=routes.filter(r=>{
   if(!q)return true;
   return Object.values(r).some(v=>String(v??"").toLowerCase().includes(q));
 });

 for(const r of filtered){
   const tr=document.createElement("tr");
   const isDefault=r.DestinationPrefix==="0.0.0.0/0"||r.DestinationPrefix==="::/0";
   if(isDefault)tr.className="default";

   tr.innerHTML=
   `<td>${esc(val(r.DestinationPrefix))}</td>`+
   `<td>${dns(r.DestinationDNS)}</td>`+
   `<td>${esc(val(r.NextHop))}</td>`+
   `<td>${dns(r.NextHopDNS)}</td>`+
   `<td>${esc(val(r.InterfaceAlias))}</td>`+
   `<td>${esc(val(r.InterfaceIndex))}</td>`+
   `<td>${esc(val(r.RouteMetric))}</td>`+
   `<td>${esc(val(r.InterfaceMetric))}</td>`+
   `<td>${esc(val(r.ProtocolDisplay))}</td>`+
   `<td><span class="badge ${String(r.State||"").toLowerCase().includes("active")?"active":""}">${esc(val(r.State))}</span></td>`+
   `<td>${esc(val(r.Type))}</td>`+
   `<td>${esc(val(r.Origin))}</td>`+
   `<td>${esc(val(r.ValidLifetime))}</td>`+
   `<td>${esc(val(r.PreferredLifetime))}</td>`+
   `<td>${esc(val(r.PolicyStore))}</td>`+
   `<td>${esc(val(r.CompartmentId))}</td>`+
   `<td>${esc(val(r.Publish))}</td>`+
   `<td>${esc(val(r.Store))}</td>`;

   body.appendChild(tr);
 }

 $("count").textContent=routes.length;
 $("ifcount").textContent=new Set(routes.map(x=>x.InterfaceAlias).filter(Boolean)).size;
 $("gwcount").textContent=new Set(routes.map(x=>x.NextHop).filter(x=>x&&x!=="0.0.0.0"&&x!=="::")).size;
 $("dnscount").textContent=routes.filter(x=>x.NextHopDNS||x.DestinationDNS).length;
}

async function load(){
 $("loading").textContent="Route tablosu okunuyor...";
 try{
   const family=$("family").value;
   const r=await fetch("/api/routes?family="+family,{cache:"no-store"});
   const data=await r.json();
   if(!r.ok)throw new Error(data.error||"Route tablosu okunamadı");
   routes=data.routes||[];
   if(data.hash!==lastHash)lastHash=data.hash;
   render();
   $("status").textContent="Son güncelleme: "+new Date().toLocaleTimeString("tr-TR");
 }catch(e){
   $("status").textContent="Hata: "+e.message;
 }finally{
   $("loading").textContent="";
 }
}

async function refreshDns(){
 $("loading").textContent="DNS çözümlemesi yapılıyor...";
 try{
   const family=$("family").value;
   const r=await fetch("/api/dns?family="+family,{cache:"no-store"});
   const data=await r.json();
   if(!r.ok)throw new Error(data.error||"DNS işlemi başarısız");
   routes=data.routes||routes;
   lastHash=data.hash||"";
   render();
   $("status").textContent="DNS güncellendi: "+new Date().toLocaleTimeString("tr-TR");
 }catch(e){
   $("status").textContent="DNS hatası: "+e.message;
 }finally{
   $("loading").textContent="";
 }
}

function schedule(){
 if(timer)clearInterval(timer);
 if($("auto").checked)
   timer=setInterval(load,Number($("interval").value)*1000);
}

$("refresh").onclick=load;
$("dnsBtn").onclick=refreshDns;
$("family").onchange=()=>{lastHash="";load();};
$("search").oninput=render;
$("auto").onchange=schedule;
$("interval").onchange=schedule;

load();
schedule();
</script>
</body>
</html>"""

DNS_CACHE={}
DNS_LOCK=threading.Lock()

# Windows Get-NetRoute / NL_ROUTE_PROTOCOL (RFC 4292 ipRouteProto) enum değerleri
class RouteProtocol(IntEnum):
    Other = 1
    Local = 2
    NetMgmt = 3
    Icmp = 4
    Egp = 5
    Ggp = 6
    Hello = 7
    Rip = 8
    IsIs = 9
    EsIs = 10
    Igrp = 11
    Bbn = 12
    Ospf = 13
    Bgp = 14
    Idpr = 15
    Eigrp = 16
    Dvmrp = 17
    Rpl = 18
    Dhcp = 19

PROTOCOL_NAMES = {p.value: p.name for p in RouteProtocol}

def protocol_display(value):
    if value is None or value == "":
        return None
    try:
        n=int(value)
        return f"{n} ({PROTOCOL_NAMES.get(n, 'Bilinmeyen')})"
    except (ValueError,TypeError):
        text=str(value)
        return text

def lifetime_text(value):
    if value is None or value=="":
        return None
    if isinstance(value,dict):
        if "Ticks" in value:
            try:
                seconds=int(value["Ticks"]) / 10_000_000
                if seconds >= 315360000:
                    return "Infinite"
                days=int(seconds//86400); seconds%=86400
                hours=int(seconds//3600); seconds%=3600
                minutes=int(seconds//60); seconds%=60
                return f"{days}.{hours:02d}:{minutes:02d}:{int(seconds):02d}"
            except Exception:
                pass
        if "Days" in value:
            return f"{value.get('Days',0)}.{value.get('Hours',0):02d}:{value.get('Minutes',0):02d}:{value.get('Seconds',0):02d}"
    return str(value)

def ps_routes(family):
    ps=(
      "$OutputEncoding=[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
      f"Get-NetRoute -AddressFamily {family} | "
      "Select-Object DestinationPrefix,NextHop,RouteMetric,InterfaceMetric,"
      "InterfaceAlias,InterfaceIndex,Protocol,State,PolicyStore,Type,Origin,"
      "@{Name='ValidLifetime';Expression={if ($_.ValidLifetime -is [TimeSpan]) {$_.ValidLifetime.ToString()} else {[string]$_.ValidLifetime}}},"
      "@{Name='PreferredLifetime';Expression={if ($_.PreferredLifetime -is [TimeSpan]) {$_.PreferredLifetime.ToString()} else {[string]$_.PreferredLifetime}}},"
      "CompartmentId,Publish,Store | ConvertTo-Json -Compress"
    )
    p=subprocess.run(
      ["powershell.exe","-NoLogo","-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-Command",ps],
      stdout=subprocess.PIPE,stderr=subprocess.PIPE,
      creationflags=subprocess.CREATE_NO_WINDOW
    )
    if p.returncode:
        raise RuntimeError(p.stderr.decode("utf-8","replace").strip() or "Get-NetRoute başarısız.")
    out=p.stdout.decode("utf-8","replace").strip()
    if not out:return []
    x=json.loads(out)
    return x if isinstance(x,list) else [x]

def normalize(r):
    out=dict(r)
    for k in ("DestinationPrefix","NextHop","InterfaceAlias","InterfaceIndex","RouteMetric","InterfaceMetric",
              "Protocol","State","PolicyStore","Type","Origin","ValidLifetime","PreferredLifetime",
              "CompartmentId","Publish","Store"):
        out.setdefault(k,None)
    out["ValidLifetime"]=lifetime_text(out["ValidLifetime"])
    out["PreferredLifetime"]=lifetime_text(out["PreferredLifetime"])
    out["ProtocolDisplay"]=protocol_display(out["Protocol"])
    out["DestinationDNS"]=None
    out["NextHopDNS"]=None
    return out

def is_resolvable_ip(value):
    if not value:return False
    try:
        ip=ipaddress.ip_address(str(value))
        return not ip.is_unspecified
    except ValueError:
        return False

def resolve_one(ip):
    if not is_resolvable_ip(ip):return None
    with DNS_LOCK:
        if ip in DNS_CACHE:return DNS_CACHE[ip]
    try:name=socket.gethostbyaddr(ip)[0]
    except (socket.herror,socket.gaierror,OSError):name=None
    with DNS_LOCK:DNS_CACHE[ip]=name
    return name

def add_dns(routes,force=False):
    if force:
        with DNS_LOCK:DNS_CACHE.clear()
    ips=set()
    for r in routes:
        nh=r.get("NextHop")
        if is_resolvable_ip(nh):ips.add(nh)
        dst=r.get("DestinationPrefix")
        try:
            net=ipaddress.ip_network(dst,strict=False)
            if net.prefixlen in (32,128) and is_resolvable_ip(str(net.network_address)):
                ips.add(str(net.network_address))
        except (ValueError,TypeError):pass
    with ThreadPoolExecutor(max_workers=12) as ex:
        futures=[ex.submit(resolve_one,ip) for ip in ips]
        for f in as_completed(futures):
            f.result()
    for r in routes:
        r["NextHopDNS"]=resolve_one(r.get("NextHop")) if is_resolvable_ip(r.get("NextHop")) else None
        dip=None
        try:
            net=ipaddress.ip_network(r.get("DestinationPrefix"),strict=False)
            if net.prefixlen in (32,128):dip=str(net.network_address)
        except (ValueError,TypeError):pass
        r["DestinationDNS"]=resolve_one(dip) if dip else None
    return routes

@app.get("/")
def index():return render_template_string(HTML)

@app.get("/api/routes")
def api_routes():
    family=request.args.get("family","IPv4")
    if family not in ("IPv4","IPv6"):family="IPv4"
    try:
        routes=[normalize(x) for x in ps_routes(family)]
        payload=json.dumps(routes,ensure_ascii=False,sort_keys=True,separators=(",",":"))
        return jsonify({"hash":hashlib.sha256(payload.encode()).hexdigest(),"routes":routes})
    except Exception as e:return jsonify({"error":str(e)}),500

@app.get("/api/dns")
def api_dns():
    family=request.args.get("family","IPv4")
    if family not in ("IPv4","IPv6"):family="IPv4"
    try:
        routes=add_dns([normalize(x) for x in ps_routes(family)],True)
        payload=json.dumps(routes,ensure_ascii=False,sort_keys=True,separators=(",",":"))
        return jsonify({"hash":hashlib.sha256(payload.encode()).hexdigest(),"routes":routes})
    except Exception as e:return jsonify({"error":str(e)}),500

if __name__=="__main__":
    parser = argparse.ArgumentParser(description="Windows 11 Route Table Monitor")
    parser.add_argument("port_pos", nargs="?", type=int, default=None, help="Port numarası (örn: 8080)")
    parser.add_argument("-p", "--port", type=int, default=None, help="Port numarası (varsayılan: 5000)")
    parser.add_argument("--host", default="127.0.0.1", help="Host adresi (varsayılan: 127.0.0.1)")
    args = parser.parse_args()

    port = args.port or args.port_pos or int(os.environ.get("PORT", 5000))
    if not (1 <= port <= 65535):
        print(f"Hata: Geçersiz port numarası ({port}). Port 1-65535 arasında olmalıdır.", file=sys.stderr)
        sys.exit(1)

    print("Windows 11 Route Table Monitor")
    print(f"http://{args.host}:{port}")
    app.run(host=args.host, port=port, debug=False, threaded=True)
