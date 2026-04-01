# generate fake login logs with users, ip addresses, success or failure
import time
import random


def generate_brute_force_logs():
    current_time = time.time()

    return [
        {"user": "admin", "ip": "203.0.113.10", "status": "FAILED", "timestamp": current_time},
        {"user": "admin", "ip": "203.0.113.10", "status": "FAILED", "timestamp": current_time + 1},
        {"user": "admin", "ip": "203.0.113.10", "status": "FAILED", "timestamp": current_time + 2},
        {"user": "admin", "ip": "203.0.113.10", "status": "FAILED", "timestamp": current_time + 3},
        {"user": "admin", "ip": "203.0.113.10", "status": "FAILED", "timestamp": current_time + 4},
        {"user": "admin", "ip": "203.0.113.10", "status": "SUCCESS", "timestamp": current_time + 5},
        {"user": "james", "ip": "192.168.1.1", "status": "SUCCESS", "timestamp": current_time + 6},
        {"user": "guest", "ip": "10.0.0.5", "status": "SUCCESS", "timestamp": current_time + 7},
    ]


def generate_credential_stuffing_logs():
    current_time = time.time()

    return [
        {"user": "admin", "ip": "198.51.100.25", "status": "FAILED", "timestamp": current_time},
        {"user": "guest", "ip": "198.51.100.25", "status": "FAILED", "timestamp": current_time + 1},
        {"user": "james", "ip": "198.51.100.25", "status": "FAILED", "timestamp": current_time + 2},
        {"user": "analyst", "ip": "198.51.100.25", "status": "FAILED", "timestamp": current_time + 3},
        {"user": "hr_user", "ip": "198.51.100.25", "status": "FAILED", "timestamp": current_time + 4},
        {"user": "james", "ip": "198.51.100.25", "status": "SUCCESS", "timestamp": current_time + 5},
        {"user": "guest", "ip": "10.0.0.5", "status": "SUCCESS", "timestamp": current_time + 6},
        {"user": "admin", "ip": "192.168.1.1", "status": "SUCCESS", "timestamp": current_time + 7},
    ]


def generate_benign_logs():
    current_time = time.time()

    return [
        {"user": "james", "ip": "192.168.1.1", "status": "SUCCESS", "timestamp": current_time},
        {"user": "guest", "ip": "10.0.0.5", "status": "SUCCESS", "timestamp": current_time + 1},
        {"user": "admin", "ip": "192.168.1.2", "status": "SUCCESS", "timestamp": current_time + 2},
        {"user": "analyst", "ip": "10.0.0.8", "status": "SUCCESS", "timestamp": current_time + 3},
        {"user": "hr_user", "ip": "192.168.1.20", "status": "SUCCESS", "timestamp": current_time + 4},
    ]


def generate_logs():
    scenarios = [
        ("Brute Force", generate_brute_force_logs),
        ("Credential Stuffing", generate_credential_stuffing_logs),
        ("Benign Activity", generate_benign_logs),
    ]

    scenario_name, scenario_function = random.choice(scenarios)
    logs = scenario_function()

    return scenario_name, logs

    
