export function root(_req, res) {
  res.json({ ok: true, service: "raees-expense-api" });
}

export function health(_req, res) {
  res.json({ status: "ok" });
}
