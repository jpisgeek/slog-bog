/** Local filtering, freshness display and a single same-origin named refresh action. */
export const fleetControls = String.raw`const settings = JSON.parse(
  document.getElementById("fleet-view-settings").textContent,
);
const state = JSON.parse(document.getElementById("fleet-state").textContent);
document.getElementById("state-report").textContent = JSON.stringify(
  state,
  null,
  2,
);
const query = document.getElementById("query"),
  group = document.getElementById("group"),
  status = document.getElementById("status");
const cards = [...document.querySelectorAll(".system")];
function filter() {
  let visible = 0;
  for (const c of cards) {
    const show = c.dataset.name.includes(query.value.toLowerCase()) &&
      (group.value === "all" || c.dataset.group === group.value) &&
      (status.value === "all" || c.dataset.health === status.value);
    c.hidden = !show;
    if (show) visible++;
  }
  document.getElementById("visible-count").textContent = visible + " of " +
    cards.length + " systems shown";
  document.getElementById("empty").hidden = visible > 0;
}
document.getElementById("filter").onclick = filter;
query.oninput = filter;
group.onchange = filter;
status.onchange = filter;
function age() {
  for (const c of cards) {
    const t = Date.parse(c.dataset.observed);
    if (
      Number.isFinite(t) && Date.now() - t > state.policy.maxAgeSeconds * 1000
    ) {
      c.dataset.health = "stale";
      const b = c.querySelector(".badge");
      b.textContent = "Stale";
      b.className = "badge stale";
    }
  }
  const current = cards.reduce((a, c) => {
    a[c.dataset.health] = (a[c.dataset.health] || 0) + 1;
    return a;
  }, {});
  document.getElementById("healthy").textContent = current.healthy || 0;
  document.getElementById("attention").textContent = current.attention || 0;
  document.getElementById("gaps").textContent = cards.length -
    (current.healthy || 0) - (current.attention || 0);
  document.getElementById("scanned").textContent =
    state.systems.filter((s) =>
      s.state === "observed" && s.sample && s.sample.osVersion!==null &&
      Date.now() - Date.parse(s.sample.observedAt) <=
        state.policy.maxAgeSeconds * 1000 &&
      Date.now() - Date.parse(s.sample.observedAt) >= -60000
    ).length;
  filter();
}
age();
setInterval(age, 30000);
const refresh = document.getElementById("refresh");
refresh.onclick = async () => {
  refresh.disabled = true;
  const message = document.getElementById("action-status");
  message.textContent = "Checking fleet through Swamp Server…";
  try {
    const r = await fetch(settings.refreshPath, {
      method: "POST",
      headers: { "X-Fleet-Action": "refresh" },
      redirect: "error",
      credentials: "same-origin",
    });
    const data = await r.json();
    if (!r.ok || data.ok !== true) throw Error();
    location.reload();
  } catch {
    message.textContent =
      "Refresh did not complete. Showing the previous snapshot; try again.";
    refresh.disabled = false;
  }
};
`;
