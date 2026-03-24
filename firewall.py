# Add this near your flood config
MAX_REQUEST_BURST = 40   # short spike allowed

def check_flood(ip):
    now = time.time()

    with _flood_lock:
        if ip in _banned_ips:
            if now < _banned_ips[ip]:
                return True
            else:
                del _banned_ips[ip]
                log.info(f"[flood] {ip} unbanned")

        times = _request_times[ip]

        # Keep last 1 second window
        times = [t for t in times if now - t < 1.0]
        times.append(now)
        _request_times[ip] = times

        # Hard limit
        if len(times) > MAX_REQUEST_BURST:
            _banned_ips[ip] = now + FLOOD_BAN_DURATION
            log.warning(f"[flood] {ip} HARD BANNED")
            return True

        # Soft limit
        if len(times) > FLOOD_THRESHOLD:
            log.warning(f"[flood] {ip} rate high")

    return False