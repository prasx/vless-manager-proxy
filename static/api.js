async function api(method, url, body) {
  const opts = { method, headers:{'Content-Type':'application/json'} };
  if (body) opts.body = JSON.stringify(body);
  try {
    const r = await fetch(url, opts);
    const data = await r.json();
    if (!r.ok && !data.error) {
      data.error = `HTTP ${r.status}`;
    }
    return data;
  } catch (e) {
    return {error: e.message};
  }
}
