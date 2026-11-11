const id=decodeURIComponent(location.hash.slice(1));location.replace('./workbench.html'+(/^CVE-\d{4}-\d{4,}$/i.test(id)?'#xray/'+id.toUpperCase():''));
