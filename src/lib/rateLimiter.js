const WINDOW_MS = 60 * 1000;
const MAX_REQUESTS = 10;

const ipMap = new Map();

export function rateLimit(ip) {
  const now = Date.now();
  const entry = ipMap.get(ip) || { count: 0, start: now };
  if (now - entry.start > WINDOW_MS) {
    entry.count = 1;
    entry.start = now;
  } else {
    entry.count += 1;
  }
  ipMap.set(ip, entry);
  if (entry.count > MAX_REQUESTS) return false;
  return true;
}
