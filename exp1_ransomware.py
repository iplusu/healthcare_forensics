"""
exp1_ransomware.py

Experiment 1: Ransomware Data Exfiltration Simulation
This script simulates a multi-stage ransomware attack aimed at data exfiltration
and evaluates different forensic triage strategies based on log volatility and 
investigation workloads.

Baselines Computed:
- Baseline A (Bulk): Plaintext bulk analysis.
- Baseline B (Indicator): Unbounded metadata-driven analysis.
- Baseline C (No Escalation): Scoped analysis without strict access control bounds.
- Proposed: Bounded escalation workflow using metadata to optimize storage overhead vs triage time.
"""

import time
import random
import json
import os
import statistics

# Globals Default
TOTAL_DB_RECORDS = 100000
EXFIL_TARGET_COUNT = 500
RECORD_SIZE_BYTES = 2048
VOLATILE_SOURCES = {"VM", "NETWORK"}

MALICIOUS_IP_1 = "192.168.100.5" 
MALICIOUS_IP_2 = "203.0.113.88" 
COMPROMISED_USER = "admin_svc"
MALICIOUS_PROCESS_STAGING = "stage_dump.sh"
MALICIOUS_PROCESS_ENCRYPT = "crypt.exe"
TEMP_BUCKET = "backup-bucket-01"

def generate_simulation(seed, config):
    """
    Generates a deterministic sequence of simulated log events (raw logs) and a set 
    of ground truth records targeted for exfiltration, modeling a multi-stage attack.
    """
    rng = random.Random(seed)
    
    ext_duration = config.get("ext_duration", 1200)
    noise_mult = config.get("noise_mult", 1.0)
    
    ground_truth_records = {f"REC_{i}" for i in range(EXFIL_TARGET_COUNT)}
    
    ts = 1700000000
    attack_events = []
    
    attack_events.append({"ts": ts, "source": "IAM", "event": "login", "user": COMPROMISED_USER, "src_ip": MALICIOUS_IP_1, "stage": "initial_access"})
    ts += 60
    attack_events.append({"ts": ts, "source": "IAM", "event": "escalate", "user": COMPROMISED_USER, "stage": "priv_esc"})
    ts += 300
    attack_events.append({"ts": ts, "source": "VM", "event": "process_start", "process": MALICIOUS_PROCESS_STAGING, "user": COMPROMISED_USER, "stage": "staging"})
    ts += 10
    
    db_extract_events = []
    for i in range(EXFIL_TARGET_COUNT):
        db_extract_events.append({"ts": ts + rng.random()*ext_duration, "source": "DB_AUDIT", "event": "read", "record_id": f"REC_{i}", "user": COMPROMISED_USER, "stage": "extraction"})
    attack_events.extend(db_extract_events)
    ts += ext_duration
    
    attack_events.append({"ts": ts, "source": "OBJ_STORE", "event": "put", "bucket": TEMP_BUCKET, "file": "dump.zip", "user": COMPROMISED_USER, "stage": "intermediate_store"})
    ts += 120
    attack_events.append({"ts": ts, "source": "NETWORK", "event": "outbound_conn", "dst_ip": MALICIOUS_IP_2, "bytes": EXFIL_TARGET_COUNT * RECORD_SIZE_BYTES, "stage": "exfiltration"})
    ts += 30
    attack_events.append({"ts": ts, "source": "VM", "event": "process_start", "process": MALICIOUS_PROCESS_ENCRYPT, "user": COMPROMISED_USER, "stage": "encryption"})

    benign_events = []
    benign_ts = 1700000000
    for _ in range(int(5000 * noise_mult)):
        benign_events.append({"ts": benign_ts + rng.random()*(ext_duration + 2000), "source": "DB_AUDIT", "event": "read", "record_id": f"REC_{rng.randint(500, TOTAL_DB_RECORDS-1)}", "user": "doctor_1"})
    for _ in range(int(100 * noise_mult)):
        benign_events.append({"ts": benign_ts - rng.random()*50000, "source": "DB_AUDIT", "event": "read", "record_id": f"REC_{rng.randint(500, TOTAL_DB_RECORDS-1)}", "user": COMPROMISED_USER})
    for _ in range(int(1000 * noise_mult)):
        benign_events.append({"ts": benign_ts + rng.random()*(ext_duration + 2000), "source": "NETWORK", "event": "outbound_conn", "dst_ip": "8.8.8.8", "bytes": rng.randint(100, 5000)})
    for _ in range(int(500 * noise_mult)):
        benign_events.append({"ts": benign_ts + rng.random()*(ext_duration + 2000), "source": "VM", "event": "process_start", "process": "svchost.exe", "user": "system"})

    raw_logs = attack_events + benign_events
    rng.shuffle(raw_logs)
    return raw_logs, ground_truth_records

def apply_volatility(events, delay_seconds, config, rng_seed):
    """
    Simulates the loss of volatile logs (e.g., VM memory, ephemeral network states)
    based on the time delay to triage and configuration rules.
    """
    rng = random.Random(rng_seed)
    base_drop_rate = config.get("drop_rate", 0.10)
    penalty_mult = config.get("delay_penalty_mult", 0.10)
    
    volatile_penalty = (delay_seconds / 600.0) * penalty_mult
    v_drop = min(0.95, base_drop_rate + volatile_penalty)
    s_drop = base_drop_rate

    filtered = []
    for ev in events:
        if ev.get("stage") == "encryption" and ev.get("source") == "VM":
            filtered.append(ev)
            continue
        drop_chance = v_drop if ev.get("source") in VOLATILE_SOURCES else s_drop
        if rng.random() > drop_chance:
            filtered.append(ev)
    return filtered, v_drop

def get_ground_truth_stages():
    """
    Returns the expected stages of a complete ransomware/exfiltration attack chain.
    """
    return {"initial_access", "priv_esc", "staging", "extraction", "intermediate_store", "exfiltration", "encryption"}

# =============================================================================
# BASELINE AND PROPOSED EVALUATION MODELS
# =============================================================================

def run_baseline_A(raw_logs, config, seed, gt_db):
    """
    Simulates Baseline A (Bulk).
    Performs full extraction of plaintext logs over a long static triage time, 
    resulting in maximum PHI exposure but highest potential recall.
    """
    triage_time = 14400 
    logs, v_drop = apply_volatility(raw_logs, triage_time, config, seed)
    
    found_stages = {ev.get("stage") for ev in logs if ev.get("stage")}
    workload = len(logs)
    acquisition_size = TOTAL_DB_RECORDS * RECORD_SIZE_BYTES + (workload * 150)
    
    return {
        "phi_exposure": TOTAL_DB_RECORDS,
        "irrelevant_phi_exposure": TOTAL_DB_RECORDS - EXFIL_TARGET_COUNT,
        "exfil_record_recall": 1.0,
        "evidentiary_stage_recall": len(found_stages) / len(get_ground_truth_stages()),
        "time_to_initial_triage": triage_time,
        "escalation_count": 0,
        "analyst_workload": workload,
        "downtime_proxy": 5, 
        "volatile_log_drop_rate": v_drop,
        "acquisition_size_mb": acquisition_size / (1024*1024)
    }

def run_baseline_B(raw_logs, config, seed, gt_db):
    """
    Simulates Baseline B (Indicator-driven).
    Triage speed depends on unstructured log count. Unbounded pull of related records 
    once an indicator is found, exposing significant collateral records.
    """
    # Dynamic Time Calculation
    raw_wk = len([l for l in raw_logs if l["source"] in ("VM", "DB_AUDIT")])
    triage_time = 60 + (raw_wk * 0.1)

    logs, v_drop = apply_volatility(raw_logs, triage_time, config, seed)
    
    workload = 0
    filtered_vm = [l for l in logs if l["source"] == "VM"]
    workload += len(filtered_vm)
    
    ioc_time, ioc_user = None, None
    for l in filtered_vm:
        if l.get("process") == MALICIOUS_PROCESS_ENCRYPT:
            ioc_time, ioc_user = l["ts"], l["user"]
            break
            
    found_records = set()
    filtered_db = [l for l in logs if l["source"] == "DB_AUDIT"]
    workload += len(filtered_db)
    
    for l in filtered_db:
        if ioc_time and ioc_user:
            if l["user"] == ioc_user and (ioc_time - 600 <= l["ts"] <= ioc_time + 60):
                if "record_id" in l:
                    found_records.add(l["record_id"])
                
    found_stages = {"encryption"}
    found_records.discard("")
    exfil_intersect = len(found_records.intersection(gt_db))

    acquisition_size = len(found_records) * RECORD_SIZE_BYTES + (workload * 150)
    
    return {
        "phi_exposure": len(found_records),
        "irrelevant_phi_exposure": len(found_records) - exfil_intersect,
        "exfil_record_recall": exfil_intersect / len(gt_db) if gt_db else 0,
        "evidentiary_stage_recall": len(found_stages) / len(get_ground_truth_stages()),
        "time_to_initial_triage": float(triage_time),
        "escalation_count": 0,
        "analyst_workload": workload,
        "downtime_proxy": 1,
        "volatile_log_drop_rate": v_drop,
        "acquisition_size_mb": acquisition_size / (1024*1024)
    }

def run_baseline_C(raw_logs, config, seed, gt_db):
    """
    Simulates Baseline C (No Escalation).
    Faster bounded search but pulls logs directly without formal escalation, 
    lowering precision of focused event exposure compared to proposed.
    """
    # Dynamic Time Calculation
    raw_wk = len([l for l in raw_logs if l["source"] in ("VM", "IAM", "DB_AUDIT")])
    triage_time = 300 + (raw_wk * 0.1)
    logs, v_drop = apply_volatility(raw_logs, triage_time, config, seed)
    
    workload = 0
    found_stages = set()
    found_records = set()
    
    filtered_vm = [l for l in logs if l["source"] == "VM"]
    workload += len(filtered_vm)
    encrypt_log = next((l for l in filtered_vm if l.get("process") == MALICIOUS_PROCESS_ENCRYPT), None)
    if encrypt_log:
        found_stages.add("encryption")
        ioc_user = encrypt_log["user"]
        
        staging_logs = [l for l in filtered_vm if l.get("user") == ioc_user and l.get("ts") < encrypt_log["ts"]]
        if staging_logs: found_stages.add("staging")
            
        filtered_iam = [l for l in logs if l["source"] == "IAM"]
        workload += len(filtered_iam)
        iam_logs = [l for l in filtered_iam if l.get("user") == ioc_user]
        if iam_logs: found_stages.add("initial_access")
        
        filtered_db = [l for l in logs if l["source"] == "DB_AUDIT"]
        workload += len(filtered_db)
        
        target_db_logs = [l for l in filtered_db if l["user"] == ioc_user]
        for l in target_db_logs:
             if "stage" in l and l["stage"] == "extraction":
                 found_stages.add("extraction")
             if "record_id" in l:
                 found_records.add(l.get("record_id"))
                 
    found_records.discard("")
    exfil_intersect = len(found_records.intersection(gt_db))

    acquisition_size = len(found_records) * RECORD_SIZE_BYTES + (workload * 150)
    
    return {
        "phi_exposure": len(found_records),
        "irrelevant_phi_exposure": len(found_records) - exfil_intersect,
        "exfil_record_recall": exfil_intersect / len(gt_db) if gt_db else 0,
        "evidentiary_stage_recall": len(found_stages) / len(get_ground_truth_stages()),
        "time_to_initial_triage": float(triage_time),
        "escalation_count": 0, 
        "analyst_workload": workload,
        "downtime_proxy": 2,
        "volatile_log_drop_rate": v_drop,
        "acquisition_size_mb": acquisition_size / (1024*1024)
    }

def run_proposed(raw_logs, config, seed, gt_db):
    """
    Simulates the Proposed Data-less/Metadata-Driven Investigation Workflow.
    Limits log pulls via strictly bounded escalation boards, significantly reducing 
    irrelevant PHI exposure while maintaining efficient forensic recall.
    """
    # Dynamic Time Calculation
    raw_wk = len(raw_logs) # checks all
    escalations = 4
    # Time = Base + Review Load + Privacy Reviews (10 mins each)
    triage_time = 300 + (raw_wk * 0.1) + (escalations * 600)
    logs, v_drop = apply_volatility(raw_logs, triage_time, config, seed)
    
    esc_count = 0
    workload = 0
    found_stages = set()
    found_records = set()
    
    filtered_vm = [l for l in logs if l["source"] == "VM"]
    workload += len(filtered_vm)
    encrypt_log = next((l for l in filtered_vm if l.get("process") == MALICIOUS_PROCESS_ENCRYPT), None)
    
    if encrypt_log:
        found_stages.add("encryption")
        ioc_user = encrypt_log["user"]
        
        staging_logs = [l for l in filtered_vm if l.get("user") == ioc_user and l.get("ts") < encrypt_log["ts"]]
        for sl in staging_logs:
            if "stage" in sl and sl["stage"] == "staging":
                found_stages.add("staging")
                break
                
        esc_count += 1
        filtered_iam = [l for l in logs if l["source"] == "IAM"]
        workload += len(filtered_iam)
        iam_logs = [l for l in filtered_iam if l.get("user") == ioc_user]
        for l in iam_logs:
            if "stage" in l and l["stage"] in ("initial_access", "priv_esc"):
                found_stages.add(l["stage"])
                
        esc_count += 1
        filtered_obj = [l for l in logs if l["source"] == "OBJ_STORE"]
        workload += len(filtered_obj)
        obj_logs = [l for l in filtered_obj if l.get("user") == ioc_user]
        for l in obj_logs:
            if "stage" in l and l["stage"] == "intermediate_store":
                found_stages.add("intermediate_store")
            
        esc_count += 1
        filtered_net = [l for l in logs if l["source"] == "NETWORK"]
        workload += len(filtered_net)
        net_logs = [l for l in filtered_net if l.get("bytes", 0) > 100000]
        if net_logs:
             found_stages.add("exfiltration")

        esc_count += 1
        filtered_db = [l for l in logs if l["source"] == "DB_AUDIT"]
        workload += len(filtered_db)
        
        time_start = min((l["ts"] for l in iam_logs), default=encrypt_log["ts"] - 3600)
        target_db_logs = [l for l in filtered_db if l["user"] == ioc_user and time_start <= l["ts"] <= encrypt_log["ts"]]
        for l in target_db_logs:
             if "stage" in l and l["stage"] == "extraction":
                 found_stages.add("extraction")
             if "record_id" in l:
                 found_records.add(l.get("record_id"))
    
    found_records.discard("")
    exfil_intersect = len(found_records.intersection(gt_db))

    acquisition_size = len(found_records) * RECORD_SIZE_BYTES + (workload * 150)

    return {
        "phi_exposure": len(found_records), 
        "irrelevant_phi_exposure": len(found_records) - exfil_intersect,
        "exfil_record_recall": exfil_intersect / len(gt_db) if gt_db else 0,
        "evidentiary_stage_recall": len(found_stages) / len(get_ground_truth_stages()),
        "time_to_initial_triage": float(triage_time), 
        "escalation_count": esc_count,
        "analyst_workload": workload, 
        "downtime_proxy": 2, 
        "volatile_log_drop_rate": v_drop,
        "acquisition_size_mb": acquisition_size / (1024*1024)
    }

def run_MC_simulation(config, runs=30):
    """
    Runs a Monte Carlo simulation over the given configurations for all models.
    Returns the aggregated mean and standard deviation of various runtime metrics.
    """
    results = {"Baseline_A": [], "Baseline_B": [], "Baseline_C_NoEscal": [], "Proposed": []}
    for seed in range(runs):
        raw_logs, gt_db = generate_simulation(seed, config)
        results["Baseline_A"].append(run_baseline_A(raw_logs, config, seed, gt_db))
        results["Baseline_B"].append(run_baseline_B(raw_logs, config, seed, gt_db))
        results["Baseline_C_NoEscal"].append(run_baseline_C(raw_logs, config, seed, gt_db))
        results["Proposed"].append(run_proposed(raw_logs, config, seed, gt_db))
        
    agg = {}
    for key, val_list in results.items():
        agg[key] = {}
        for metric in val_list[0].keys():
            arr = [x[metric] for x in val_list]
            agg[key][metric] = {
                "mean": round(statistics.mean(arr), 4),
                "std": round(statistics.stdev(arr), 4) if runs > 1 else 0
            }
    return agg

if __name__ == "__main__":
    print("--- Running Advanced Ransomware Simulation ---")
    
    base_config = {"drop_rate": 0.10, "delay_penalty_mult": 0.10, "ext_duration": 1200, "noise_mult": 1.0}
    res_base = run_MC_simulation(base_config, runs=30)
    
    import copy
    sensitivity = {}
    
    sensitivity["drop_rate"] = {}
    for dr in [0.05, 0.10, 0.20, 0.30]:
        cfg = copy.deepcopy(base_config)
        cfg["drop_rate"] = dr
        sensitivity["drop_rate"][str(dr)] = run_MC_simulation(cfg, runs=30)
        
    sensitivity["ext_duration"] = {}
    for ed in [60, 600, 1200, 3600]:
        cfg = copy.deepcopy(base_config)
        cfg["ext_duration"] = ed
        sensitivity["ext_duration"][str(ed)] = run_MC_simulation(cfg, runs=30)

    sensitivity["noise_mult"] = {}
    for nm in [0.5, 1.0, 2.0, 5.0]:
        cfg = copy.deepcopy(base_config)
        cfg["noise_mult"] = nm
        sensitivity["noise_mult"][str(nm)] = run_MC_simulation(cfg, runs=30)
        
    sensitivity["delay_penalty_mult"] = {}
    for dpm in [0.05, 0.10, 0.20, 0.50]:
        cfg = copy.deepcopy(base_config)
        cfg["delay_penalty_mult"] = dpm
        sensitivity["delay_penalty_mult"][str(dpm)] = run_MC_simulation(cfg, runs=30)

    final_output = {
        "baseline_N30": res_base,
        "sensitivity": sensitivity
    }
    
    os.makedirs("results", exist_ok=True)
    out_file = "results/results_exp1_advanced.json"
    with open(out_file, "w") as f:
        json.dump(final_output, f, indent=4)
        
    print(f"Done. Output saved to {out_file}")
