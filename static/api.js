async function api(method, url, body) {
  const opts = { method, headers:{'Content-Type':'application/json'} };
  if (body) opts.body = JSON.stringify(body);
  try {
    const r = await fetch(url, opts);
    return await r.json();
  } catch (e) {
    return {error: e.message};
  }
}
