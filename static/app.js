const form = document.getElementById('uploadForm');
const progressBar = document.getElementById('progressBar');
const resultArea = document.getElementById('resultArea');
const acceptedTable = document.getElementById('acceptedTable');
const summaryText = document.getElementById('summaryText');
const suspectsList = document.getElementById('suspectsList');
const suspectsMapEl = document.getElementById('suspectsMap');
const suspectsTitle = document.getElementById('suspectsTitle');
const noBruteModalEl = document.getElementById('noBruteModal');
const userOps = document.getElementById('userOps');
const resetBtn = document.getElementById('resetBtn');

let taskId = null;
let noBruteModal;

function setProgress(p){
  const v = Math.max(0, Math.min(100, p));
  progressBar.style.width = v + '%';
  progressBar.textContent = v + '%';
}

function poll(){
  if(!taskId) return;
  fetch('/progress/' + taskId)
    .then(r=>r.json())
    .then(d=>{
      if(d.progress !== undefined) setProgress(d.progress);
      if(d.status === 'done'){
        fetch('/result/' + taskId)
          .then(r=>r.json())
          .then(showResult);
      } else {
        setTimeout(poll, 800);
      }
    });
}

function showResult(res){
  resultArea.classList.remove('d-none');
  const bf = res.bruteforce ? '是' : '否';
  summaryText.textContent = `文件: ${res.file} | 暴力破解: ${bf} | 成功登录次数: ${res.stats.accepted_total} | 失败登录次数: ${res.stats.failed_total}`;
  suspectsList.innerHTML = '';
  const details = res.suspects_detail || [];
  if(details.length){
    if(suspectsTitle){
      const ips = details.map(d=>d.ip).join('、');
      suspectsTitle.textContent = `可疑攻击者IP：${ips}`;
    }
    const bounds = [];
    details.forEach(d=>{
      const li = document.createElement('li');
      const loc = [d.country, d.region, d.city].filter(Boolean).join(' / ');
      const ll = (d.lat != null && d.lon != null) ? ` - 经纬度: ${d.lat}, ${d.lon}` : '';
      li.textContent = `${loc}${ll}`;
      suspectsList.appendChild(li);
      if(d.lat != null && d.lon != null) bounds.push([d.lat, d.lon, d]);
    });
    if(suspectsMapEl){
      if(suspectsMap){
        suspectsMap.remove();
      }
      suspectsMap = L.map('suspectsMap');
      const tiles = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 18 });
      tiles.addTo(suspectsMap);
      if(bounds.length){
        const latlngs = bounds.map(b=>[b[0], b[1]]);
        latlngs.forEach((ll, i)=>{
          const d = bounds[i][2];
          const loc = [d.country, d.region, d.city].filter(Boolean).join(' / ');
          const popup = `${loc || d.ip}`;
          L.marker(ll).addTo(suspectsMap).bindPopup(popup);
        });
        if(latlngs.length === 1){
          suspectsMap.setView(latlngs[0], 9);
        } else {
          suspectsMap.fitBounds(latlngs, { padding: [20,20] });
        }
      } else {
        suspectsMap.setView([20,0], 2);
      }
    }
  } else {
    if(suspectsTitle){
      suspectsTitle.textContent = '可疑攻击者IP：无';
    }
    const li = document.createElement('li');
    li.textContent = '无';
    suspectsList.appendChild(li);
    if(suspectsMapEl && suspectsMap){
      suspectsMap.remove();
      suspectsMap = null;
    }
  }
  userOps.innerHTML = '';
  if(res.user_operations){
    const wrapper = document.createElement('div');
    wrapper.className = 'table-responsive';
    const table = document.createElement('table');
    table.className = 'table table-sm table-striped align-middle';
    const thead = document.createElement('thead');
    const trh = document.createElement('tr');
    ['时间','用户','原始日志'].forEach(h=>{ const th = document.createElement('th'); th.textContent = h; trh.appendChild(th); });
    thead.appendChild(trh);
    const tbody = document.createElement('tbody');
    const rows = [];
    Object.keys(res.user_operations).forEach(subject=>{
      res.user_operations[subject].forEach(item=>{
        rows.push({ ts: item.timestamp, subject, raw: item.raw || '' });
      });
    });
    rows.forEach(r=>{
      const tr = document.createElement('tr');
      [r.ts, r.subject, r.raw].forEach(v=>{ const td = document.createElement('td'); td.textContent = v; tr.appendChild(td); });
      tbody.appendChild(tr);
    });
    table.appendChild(thead);
    table.appendChild(tbody);
    wrapper.appendChild(table);
    userOps.appendChild(wrapper);
  }
  acceptedTable.innerHTML = '';
  res.accepted_events.forEach(e=>{
    const tr = document.createElement('tr');
    [e.timestamp, e.ip, e.user, e.port].forEach(v=>{
      const td = document.createElement('td');
      td.textContent = v;
      tr.appendChild(td);
    });
    acceptedTable.appendChild(tr);
  });
}

form.addEventListener('submit', function(ev){
  ev.preventDefault();
  resultArea.classList.add('d-none');
  setProgress(0);
  const fd = new FormData(form);
  fetch('/analyze', { method: 'POST', body: fd })
    .then(r=>r.json())
    .then(d=>{
      taskId = d.task_id;
      poll();
    });
});

resetBtn.addEventListener('click', function(){
  form.reset();
  setProgress(0);
  resultArea.classList.add('d-none');
});
let suspectsMap;
