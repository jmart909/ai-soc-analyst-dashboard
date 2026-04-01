def detect_threats(logs):
    alerts = []

    failed_logins = [log for log in logs if log["status"] == "FAILED"]

    # -----------------------------
    # 1. Brute Force Detection
    # Same user + many failures
    # -----------------------------
    user_failures = {}
    user_failed_ips = {}

    for log in failed_logins:
        user = log["user"]
        ip = log["ip"]

        user_failures[user] = user_failures.get(user, 0) + 1

        if user not in user_failed_ips:
            user_failed_ips[user] = {}

        user_failed_ips[user][ip] = user_failed_ips[user].get(ip, 0) + 1

    for user, count in user_failures.items():
        if count >= 5:
            suspicious_ip = max(user_failed_ips[user], key=user_failed_ips[user].get)

            alerts.append({
                "type": "Brute Force Attempt",
                "severity": "High",
                "description": f"Multiple failed login attempts detected for user '{user}'",
                "mitre_technique": "T1110 - Brute Force",
                "risk_score": 90,
                "source_ip": suspicious_ip
            })
            return alerts

    # -----------------------------
    # 2. Credential Stuffing Detection
    # Same IP + many users failing
    # -----------------------------
    ip_users = {}

    for log in failed_logins:
        ip = log["ip"]
        user = log["user"]

        if ip not in ip_users:
            ip_users[ip] = set()

        ip_users[ip].add(user)

    for ip, users in ip_users.items():
        if len(users) >= 4:
            alerts.append({
                "type": "Credential Stuffing",
                "severity": "High",
                "description": f"Multiple users targeted from IP {ip}",
                "mitre_technique": "T1110 - Credential Stuffing",
                "risk_score": 85,
                "source_ip": ip
            })
            return alerts

    # -----------------------------
    # 3. No Threat
    # -----------------------------
    return alerts
