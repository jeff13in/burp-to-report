async function req(path, opts = {}) {
  const r = await fetch(path, opts);
  if (!r.ok) {
    let msg = `${r.status}`;
    try { msg = (await r.json()).detail || msg; } catch { /* not json */ }
    throw new Error(msg);
  }
  const type = r.headers.get("content-type") || "";
  return type.includes("json") ? r.json() : r.text();
}

export const api = {
  health: () => req("/api/health"),
  upload: (file, name, scope) => {
    const fd = new FormData();
    fd.append("file", file);
    fd.append("name", name || file.name);
    fd.append("scope", scope || "");
    return req("/api/projects", { method: "POST", body: fd });
  },
  demo: () => req("/api/demo", { method: "POST" }),
  exchange: (pid, eid) => req(`/api/projects/${pid}/exchanges/${eid}`),
  update: (pid, fid, patch) =>
    req(`/api/projects/${pid}/findings/${fid}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(patch),
    }),
  report: (pid, includePending) => req(`/api/projects/${pid}/report?include_pending=${includePending}`),
};
