'use strict';
// In-memory only, per the "live ticks are ephemeral, no persistence"
// requirement - this is what makes the admin Live Monitor feel live
// (ticking rupees/litres mid-fill) without writing to Turso on every
// packet a station forwards. It's fed by both durable 'event' messages
// (real status changes, which also get persisted - see lib/db.js) and
// ephemeral 'live' ticks (same status, just the numbers moving), so a
// connected station's view is always current regardless of which kind of
// message last arrived. Lost on restart by design; db.listNozzleState()
// is the fallback for stations that haven't sent anything since then.
class LiveState {
  constructor() {
    this.stations = new Map(); // stationId -> { connected, lastEventAt, nozzles: Map<noz, state> }
  }

  _get(stationId) {
    let s = this.stations.get(stationId);
    if (!s) {
      s = { connected: false, lastEventAt: null, nozzles: new Map() };
      this.stations.set(stationId, s);
    }
    return s;
  }

  setConnected(stationId, connected) {
    this._get(stationId).connected = connected;
  }

  updateNozzle(stationId, nozzleState) {
    const s = this._get(stationId);
    s.nozzles.set(nozzleState.num, nozzleState);
    s.lastEventAt = new Date().toISOString();
  }

  snapshot(stationId) {
    const s = this.stations.get(stationId);
    if (!s) return { connected: false, lastEventAt: null, nozzles: [] };
    return { connected: s.connected, lastEventAt: s.lastEventAt, nozzles: [...s.nozzles.values()] };
  }
}

module.exports = { LiveState };
