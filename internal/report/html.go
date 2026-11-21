package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/DonobanR/kagemusha/internal/model"
	"github.com/DonobanR/kagemusha/internal/stix"
)

// ToHTML generates a self-contained HTML file with an interactive
// force-directed graph visualization of the STIX bundle.
func ToHTML(results []model.Result, now time.Time) ([]byte, error) {
	bundle := stix.ToBundle(results, now)
	data, err := json.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("marshaling STIX bundle: %w", err)
	}
	out := strings.Replace(tmpl, `"__STIX_DATA__"`, string(data), 1)
	return []byte(out), nil
}

const tmpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kagemusha IOC Graph</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#12121f;overflow:hidden;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;display:flex;flex-direction:column;height:100vh;color:#c8c8d8}
.bar{display:flex;align-items:center;justify-content:space-between;padding:8px 16px;background:#1a1a2e;border-bottom:1px solid #2d2d3f}
.bar .lo{color:#a0a0b8;font-size:12px;font-weight:500;letter-spacing:.5px}
.bar .tg{font-size:10px;color:#5a5a72;padding:1px 6px;border:1px solid #2d2d3f;border-radius:3px;margin-left:8px}
.wr{display:flex;flex:1;overflow:hidden}
#g{display:block;flex:1}
#p{width:280px;background:#1a1a2e;border-left:1px solid #2d2d3f;overflow-y:auto;font-size:12px}
.ph{padding:14px 16px;border-bottom:1px solid #2d2d3f}
.ph .bg{display:flex;gap:6px;margin-bottom:6px}
.ph .bd{font-size:10px;padding:1px 6px;border-radius:3px}
.ph .bt{background:#2d2d3f;color:#a0a0b8}
.ph .nm{font-size:16px;font-weight:500;color:#e8e8f0;letter-spacing:-.3px}
.ph .sb{font-size:10px;color:#5a5a72;margin-top:4px}
.sg{display:grid;grid-template-columns:1fr 1fr;border-bottom:1px solid #2d2d3f}
.sg .c{padding:10px 16px}
.sg .c+.c{border-left:1px solid #2d2d3f}
.sg .l{font-size:10px;color:#5a5a72;text-transform:uppercase;letter-spacing:.3px}
.sg .v{font-size:13px;font-weight:500;margin-top:2px}
.ps{padding:12px 16px;border-bottom:1px solid #2d2d3f}
.ps .st{font-size:10px;color:#5a5a72;text-transform:uppercase;letter-spacing:.3px;margin-bottom:8px}
.rl{display:flex;align-items:center;gap:8px;padding:7px 10px;margin-bottom:4px;background:#12121f;border:1px solid #2d2d3f;border-radius:4px;color:#7b8aff;text-decoration:none;font-size:11px}
.rl:hover{border-color:#7b8aff}
.rl .rn{font-weight:500;display:block}
.rl .rd{color:#5a5a72;font-size:10px}
.rl .ri{font-size:14px;color:#5a5a72;flex-shrink:0}
.ds{font-size:11px;color:#a0a0b8;line-height:1.5;user-select:text}
.pl{display:flex;flex-wrap:wrap;gap:4px}
.pl span{font-size:10px;padding:3px 8px;border-radius:3px}
.em{color:#5a5a72;font-size:12px;padding:60px 16px;text-align:center;line-height:1.6}
.lg{padding:8px 16px;background:#1a1a2e;border-top:1px solid #2d2d3f;display:flex;justify-content:center;gap:16px;font-size:10px;color:#5a5a72}
.lg span{display:flex;align-items:center;gap:4px}
.lg i{width:7px;height:7px;border-radius:50%;display:inline-block}
#t{position:fixed;display:none;background:#1a1a2e;border:1px solid #2d2d3f;border-radius:6px;padding:8px 12px;font-size:12px;color:#c8c8d8;max-width:260px;z-index:10;pointer-events:none}
#t .tn{font-weight:500;font-size:12px;color:#e8e8f0}
#t .tv{font-size:11px;color:#5a5a72;margin-top:2px}
</style>
</head>
<body>
<div class="bar"><div><span class="lo">KAGEMUSHA</span><span class="tg">IOC Graph</span></div><div style="display:flex;gap:6px"><span class="tg">Scroll: zoom</span><span class="tg">Drag: pan</span></div></div>
<div class="wr">
<svg id="g"></svg>
<div id="p"><div class="em">Click a node to inspect</div></div>
</div>
<div id="t"></div>
<div class="lg">
<span><i style="background:#4a4a5e"></i>Unknown</span>
<span><i style="background:#2d6a3e"></i>Low</span>
<span><i style="background:#8a7a2a"></i>Medium</span>
<span><i style="background:#c4722a"></i>High</span>
<span><i style="background:#b03040"></i>Critical</span>
<span><i style="background:#8b3040"></i>Malware</span>
</div>
<script>
window.onload=function(){
var B="__STIX_DATA__";
var svg=document.getElementById("g");
var sr=svg.getBoundingClientRect();
var W=sr.width||520,H=sr.height||450;
var ns=[],ls=[],byId={},drag=null,alpha=1,sel=null,moved=false;

for(var k=0;k<B.objects.length;k++){
var o=B.objects[k];
if(o.type==="indicator"){
var v=(o.indicator_types||[])[0]||"unknown";
var n={id:o.id,tp:"indicator",name:o.name,desc:o.description||"",
verdict:v,conf:o.confidence||0,refs:o.external_references||[],
x:0,y:0,vx:0,vy:0,r:24,fx:false};
ns.push(n);byId[n.id]=n;
}else if(o.type==="malware"){
var n={id:o.id,tp:"malware",name:o.name,
x:0,y:0,vx:0,vy:0,r:16,fx:false};
ns.push(n);byId[n.id]=n;
}else if(o.type==="relationship"){
ls.push({s:o.source_ref,t:o.target_ref});
}}

function cc(n){
if(n.tp==="malware")return{f:"#8b3040",s:"#6b2030"};
var c=n.conf||0;
if(c===0)return{f:"#4a4a5e",s:"#3d3d55"};
if(c<=30)return{f:"#2d6a3e",s:"#245832"};
if(c<=60)return{f:"#8a7a2a",s:"#6a5a1a"};
if(c<=80)return{f:"#c4722a",s:"#a4521a"};
return{f:"#b03040",s:"#902030"};
}
function lvl(c){
if(c===0)return"unknown";if(c<=30)return"low";
if(c<=60)return"medium";if(c<=80)return"high";return"critical";
}
function esc(s){return(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;")}
function hexRgb(h){return parseInt(h.slice(1,3),16)+","+parseInt(h.slice(3,5),16)+","+parseInt(h.slice(5,7),16)}

var inds=ns.filter(function(n){return n.tp==="indicator"});
var mals=ns.filter(function(n){return n.tp==="malware"});
inds.forEach(function(n,i){
var a=2*Math.PI*i/(inds.length||1);
n.x=W/2+120*Math.cos(a);n.y=H/2+120*Math.sin(a);
});
mals.forEach(function(n,i){
var a=2*Math.PI*i/(mals.length||1)+0.4;
n.x=W/2+250*Math.cos(a);n.y=H/2+250*Math.sin(a);
});

svg.setAttribute("viewBox","0 0 "+W+" "+H);
var zm=1,px=0,py=0;
function updView(){svg.setAttribute("viewBox",px+" "+py+" "+W/zm+" "+H/zm)}
function s2svg(sx,sy){var r=svg.getBoundingClientRect();return{x:px+(sx-r.left)/r.width*(W/zm),y:py+(sy-r.top)/r.height*(H/zm)}}
function ce(t){return document.createElementNS("http://www.w3.org/2000/svg",t)}

var defs=ce("defs");
var mk=ce("marker");
mk.setAttribute("id","arr");mk.setAttribute("viewBox","0 0 10 10");
mk.setAttribute("refX","10");mk.setAttribute("refY","5");
mk.setAttribute("markerWidth","8");mk.setAttribute("markerHeight","8");
mk.setAttribute("orient","auto");
var mp=ce("path");mp.setAttribute("d","M0,0L10,5L0,10z");
mp.setAttribute("fill","#3d3d55");
mk.appendChild(mp);defs.appendChild(mk);svg.appendChild(defs);

var lineEls=ls.map(function(l){
var el=ce("line");
el.setAttribute("stroke","#3d3d55");el.setAttribute("stroke-width","1");
el.setAttribute("marker-end","url(#arr)");
svg.appendChild(el);return el;
});

var nodeEls=ns.map(function(n){
var g=ce("g");g.style.cursor="pointer";
var c=ce("circle");c.setAttribute("r",n.r);
var col=cc(n);
c.setAttribute("fill",col.f);c.setAttribute("opacity","0.9");
c.setAttribute("stroke",col.s);c.setAttribute("stroke-width","1");
g.appendChild(c);
var label=n.name;
if(n.tp==="malware"&&label.indexOf(" | ")>-1)label=label.split(" | ")[0];
if(label.length>22)label=label.slice(0,20)+"…";
var t=ce("text");t.textContent=label;
t.setAttribute("text-anchor","middle");t.setAttribute("dy",n.r+14);
t.setAttribute("fill","#a0a0b8");t.setAttribute("font-size","10");
t.setAttribute("font-family","-apple-system,system-ui,sans-serif");
g.appendChild(t);svg.appendChild(g);return g;
});

var selEl=ce("circle");
selEl.setAttribute("fill","none");selEl.setAttribute("stroke","#7b8aff");
selEl.setAttribute("stroke-width","2");selEl.setAttribute("stroke-dasharray","4 2");
selEl.setAttribute("opacity","0.5");selEl.setAttribute("r","0");
svg.appendChild(selEl);

function linked(n){
var out=[];
for(var i=0;i<ls.length;i++){
if(ls[i].s===n.id&&byId[ls[i].t])out.push(byId[ls[i].t]);
if(ls[i].t===n.id&&byId[ls[i].s])out.push(byId[ls[i].s]);
}return out;
}
function firstSeen(n){
if(!n.refs)return"—";
var d=null;
for(var i=0;i<n.refs.length;i++){
var m=(n.refs[i].description||"").match(/first seen: ([\dT:.Z-]+)/);
if(m){var t=new Date(m[1]);if(!d||t<d)d=t;}}
return d?d.toISOString().slice(0,10):"—";
}

function showPanel(n){
var p=document.getElementById("p"),col=cc(n),h="";
h+='<div class="ph"><div class="bg">';
h+='<span class="bd bt">'+(n.tp==="indicator"?"IP":"Malware")+"</span>";
if(n.tp==="indicator")h+='<span class="bd" style="background:rgba('+hexRgb(col.f)+',.15);color:'+col.f+'">'+n.conf+'/100</span>';
h+='</div><div class="nm">'+esc(n.name)+"</div>";
if(n.tp==="indicator")h+='<div class="sb">Confidence: '+lvl(n.conf)+". Scores are heuristic.</div>";
h+="</div>";
if(n.tp==="indicator"){
var vl=n.verdict.replace(/-activity$/,"");
h+='<div class="sg"><div class="c"><div class="l">VERDICT</div><div class="v" style="color:'+col.f+'">'+esc(vl)+'</div></div>';
h+='<div class="c"><div class="l">CONFIDENCE</div><div class="v" style="color:'+col.f+'">'+n.conf+'%</div></div></div>';
h+='<div class="sg"><div class="c"><div class="l">FIRST SEEN</div><div class="v" style="color:#c8c8d8">'+firstSeen(n)+'</div></div>';
h+='<div class="c"><div class="l">SOURCES</div><div class="v" style="color:#c8c8d8">'+(n.refs?n.refs.length:0)+' hits</div></div></div>';
}
if(n.refs&&n.refs.length){
h+='<div class="ps"><div class="st">REFERENCES</div>';
for(var j=0;j<n.refs.length;j++){
var r=n.refs[j];if(!r.url)continue;
h+='<a class="rl" href="'+esc(r.url)+'" target="_blank"><span class="ri">↗</span><div><span class="rn">'+esc(r.source_name)+'</span>';
if(r.description)h+='<span class="rd">'+esc(r.description)+'</span>';
h+='</div></a>';}
h+="</div>";}
if(n.desc){
h+='<div class="ps"><div class="st">DESCRIPTION</div><div class="ds">'+esc(n.desc)+'</div></div>';}
var lk=linked(n);
if(lk.length){
h+='<div class="ps"><div class="st">LINKED NODES</div><div class="pl">';
for(var j=0;j<lk.length;j++){
var ln=lk[j],lc=cc(ln),lb=ln.name;
if(ln.tp==="malware"&&lb.indexOf(" | ")>-1)lb=lb.split(" | ")[0];
h+='<span style="background:rgba('+hexRgb(lc.f)+',.2);color:'+lc.f+'">'+esc(lb)+'</span>';}
h+='</div></div>';}
p.innerHTML=h;
}

var tip=document.getElementById("t");
nodeEls.forEach(function(g,i){
var n=ns[i];
g.addEventListener("mouseenter",function(){
var col=cc(n);
var h='<div class="tn">'+esc(n.name)+"</div>";
if(n.tp==="indicator")h+='<div class="tv">'+lvl(n.conf)+" ("+n.conf+"%)</div>";
else h+='<div class="tv">Malware family</div>';
tip.innerHTML=h;tip.style.display="block";
});
g.addEventListener("mousemove",function(e){
var x=e.clientX+12,y=e.clientY+12;
if(x+260>innerWidth)x=e.clientX-272;
tip.style.left=x+"px";tip.style.top=y+"px";
});
g.addEventListener("mouseleave",function(){tip.style.display="none"});
g.addEventListener("click",function(e){
if(moved)return;
sel=n;selEl.setAttribute("r",n.r+6);
showPanel(n);
});
});

function tick(){
if(alpha<0.001&&!drag){render();return}
alpha*=0.995;
var i,j,dx,dy,d2,d,f,fx,fy;
for(i=0;i<ns.length;i++){
for(j=i+1;j<ns.length;j++){
dx=ns[j].x-ns[i].x;dy=ns[j].y-ns[i].y;
d2=dx*dx+dy*dy;if(d2<1)d2=1;d=Math.sqrt(d2);
f=alpha*6000/d2;fx=f*dx/d;fy=f*dy/d;
if(!ns[i].fx){ns[i].vx-=fx;ns[i].vy-=fy}
if(!ns[j].fx){ns[j].vx+=fx;ns[j].vy+=fy}
}}
for(i=0;i<ls.length;i++){
var s=byId[ls[i].s],t=byId[ls[i].t];
if(!s||!t)continue;
dx=t.x-s.x;dy=t.y-s.y;d=Math.sqrt(dx*dx+dy*dy)||1;
f=alpha*(d-150)*0.008;fx=f*dx/d;fy=f*dy/d;
if(!s.fx){s.vx+=fx;s.vy+=fy}
if(!t.fx){t.vx-=fx;t.vy-=fy}
}
for(i=0;i<ns.length;i++){
if(ns[i].fx)continue;
ns[i].vx+=(W/2-ns[i].x)*alpha*0.005;
ns[i].vy+=(H/2-ns[i].y)*alpha*0.005;
ns[i].vx*=0.6;ns[i].vy*=0.6;
ns[i].x+=ns[i].vx;ns[i].y+=ns[i].vy;
ns[i].x=Math.max(40,Math.min(W-40,ns[i].x));
ns[i].y=Math.max(40,Math.min(H-40,ns[i].y));
}
render();requestAnimationFrame(tick);
}

function render(){
for(var i=0;i<ls.length;i++){
var s=byId[ls[i].s],t=byId[ls[i].t];
if(!s||!t)continue;
var dx=t.x-s.x,dy=t.y-s.y;
var d=Math.sqrt(dx*dx+dy*dy)||1;
lineEls[i].setAttribute("x1",s.x+s.r*dx/d);
lineEls[i].setAttribute("y1",s.y+s.r*dy/d);
lineEls[i].setAttribute("x2",t.x-t.r*dx/d);
lineEls[i].setAttribute("y2",t.y-t.r*dy/d);
}
for(var i=0;i<ns.length;i++){
nodeEls[i].setAttribute("transform","translate("+ns[i].x+","+ns[i].y+")");
}
if(sel){selEl.setAttribute("cx",sel.x);selEl.setAttribute("cy",sel.y);}
}

var pan=false,panSt={x:0,y:0};
svg.addEventListener("mousedown",function(e){
moved=false;
for(var i=0;i<nodeEls.length;i++){
if(nodeEls[i].contains(e.target)){
drag=ns[i];drag.fx=true;alpha=Math.max(alpha,0.3);
svg.style.cursor="grabbing";e.preventDefault();return;
}}
pan=true;panSt={x:e.clientX,y:e.clientY};svg.style.cursor="move";e.preventDefault();
});
addEventListener("mousemove",function(e){
if(drag){moved=true;var p=s2svg(e.clientX,e.clientY);drag.x=p.x;drag.y=p.y;drag.vx=0;drag.vy=0;return}
if(pan){moved=true;var r=svg.getBoundingClientRect(),vw=W/zm;
px-=(e.clientX-panSt.x)/r.width*vw;py-=(e.clientY-panSt.y)/r.height*(H/zm);
panSt={x:e.clientX,y:e.clientY};updView()}
});
addEventListener("mouseup",function(){
if(drag){drag.fx=false;drag=null}pan=false;svg.style.cursor="";
});
svg.addEventListener("wheel",function(e){
e.preventDefault();
var d=e.deltaY>0?0.9:1.1,nz=Math.max(0.3,Math.min(5,zm*d));
var r=svg.getBoundingClientRect(),mx=(e.clientX-r.left)/r.width,my=(e.clientY-r.top)/r.height;
var ow=W/zm,oh=H/zm,nw=W/nz,nh=H/nz;
px+=(ow-nw)*mx;py+=(oh-nh)*my;zm=nz;updView();
},{passive:false});

requestAnimationFrame(tick);
};
</script>
</body>
</html>`
