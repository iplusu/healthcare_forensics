"""
exp2_insider.py

Experiment 2: Insider Threat Data Snooping & Governance
This script simulates user access logs over a period across different clinical roles,
injecting anomalous "snooping" behaviors. It then evaluates metadata-driven 
anomaly detection and compares review governance models in terms of analyst 
workloads vs PHI exposure.
"""

import random
import json
import os
import statistics

# Set fixed configs
NUM_USERS = 100
SIMULATION_DAYS = 30

ROLES = {
    "nurse": {"prob": 0.40, "base_vol": 100, "out_unit_pr": 0.05, "night_pr": 0.20, "bulk_pr": 0.01},
    "physician": {"prob": 0.25, "base_vol": 60, "out_unit_pr": 0.30, "night_pr": 0.10, "bulk_pr": 0.05},
    "float_nurse": {"prob": 0.10, "base_vol": 80, "out_unit_pr": 0.80, "night_pr": 0.50, "bulk_pr": 0.02}, # High native noise
    "billing": {"prob": 0.10, "base_vol": 200, "out_unit_pr": 0.00, "night_pr": 0.00, "bulk_pr": 0.90}, # Huge volume, strict hours
    "privacy_officer": {"prob": 0.05, "base_vol": 20, "out_unit_pr": 0.95, "night_pr": 0.05, "bulk_pr": 0.10},
    "on_call": {"prob": 0.10, "base_vol": 30, "out_unit_pr": 0.50, "night_pr": 0.80, "bulk_pr": 0.05}
}

MALICIOUS_PROFILES = [
    {"type": "snooping", "vol_mult": 1.0, "out_unit_boost": 0.1, "night_boost": 0.0, "vip_boost": 0.8},
    {"type": "low_and_slow", "vol_mult": 1.1, "out_unit_boost": 0.2, "night_boost": 0.2, "vip_boost": 0.0},
    {"type": "credential_theft", "vol_mult": 5.0, "out_unit_boost": 0.9, "night_boost": 0.9, "vip_boost": 0.0}
]

def generate_role(rng):
    """
    Samples a clinical/administrative role based on predefined probabilities.
    """
    r = rng.random()
    cum = 0
    for role, params in ROLES.items():
        cum += params["prob"]
        if r <= cum:
            return role
    return "nurse"

def generate_dataset(seed):
    """
    Generates the log dataset mapping clinical roles to baseline usage patterns 
    (volume, off-hours, bulk access, out-of-unit access) and injects multi-profile 
    insider threat anomalies for roughly 5% of users.
    """
    rng = random.Random(seed)
    
    users = {}
    malicious_users = set()
    
    # 5% of users are malicious
    num_malicious = max(1, int(NUM_USERS * 0.05))
    malicious_ids = rng.sample(range(1, NUM_USERS + 1), num_malicious)
    
    logs = []
    
    for uid in range(1, NUM_USERS + 1):
        role = generate_role(rng)
        is_malicious = uid in malicious_ids
        
        if is_malicious:
            malicious_users.add(uid)
            mal_profile = rng.choice(MALICIOUS_PROFILES)
        else:
            mal_profile = None

        r_params = ROLES[role]
        
        # User inherent variance
        usr_vol_mult = rng.uniform(0.5, 1.5)
        if mal_profile: usr_vol_mult *= mal_profile["vol_mult"]
        
        total_accesses = int(r_params["base_vol"] * SIMULATION_DAYS * usr_vol_mult)
        
        # Base probabilities
        p_out = r_params["out_unit_pr"]
        p_night = r_params["night_pr"]
        p_bulk = r_params["bulk_pr"]
        p_vip = 0.01 
        
        # Anomaly Events (Benign Spikes)
        if not is_malicious and rng.random() < 0.1:
            # 10% chance of a benign user having a crazy spike (e.g. Break glass)
            p_out = min(1.0, p_out + 0.4)
            p_night = min(1.0, p_night + 0.5)

        # Malicious modifications
        if is_malicious:
            p_out = min(1.0, p_out + mal_profile["out_unit_boost"])
            p_night = min(1.0, p_night + mal_profile["night_boost"])
            p_vip = min(1.0, p_vip + mal_profile["vip_boost"])
            
        users[uid] = {"role": role, "is_malicious": is_malicious, "log_count": total_accesses, "mal_profile": mal_profile["type"] if mal_profile else "benign"}
        
        # Generate Log Records
        for _ in range(total_accesses):
            is_out = 1 if rng.random() < p_out else 0
            is_night = 1 if rng.random() < p_night else 0
            is_bulk = 1 if rng.random() < p_bulk else 0
            is_vip = 1 if rng.random() < p_vip else 0
            
            # Anomalous sessions are marked mathematically for tracking 
            is_anomaly_session = (is_out or is_night or is_vip)
            
            logs.append({
                "uid": uid,
                "role": role,
                "out_unit": is_out,
                "night": is_night,
                "bulk": is_bulk,
                "vip": is_vip,
                "is_anomalous_session": is_anomaly_session
            })
            
    return users, malicious_users, logs

# =============================================================================
# ANOMALY DETECTION AND THRESHOLD EVALUATION
# =============================================================================

def calculate_risk_scores(users, logs):
    """
    Calculates dynamic Z-scores per role to identify behavioral deviations 
    relative to peer baselines (e.g., excessive night shifts or out-of-unit views).
    """
    stats = {uid: {"total": 0, "out": 0.0, "night": 0.0, "bulk": 0.0} for uid in users.keys()}
    
    for l in logs:
        u = l["uid"]
        stats[u]["total"] += 1
        stats[u]["out"] += l["out_unit"]
        stats[u]["night"] += l["night"]
        stats[u]["bulk"] += l["bulk"]
        
    role_aggregates = {r: {"out_rates": [], "night_rates": []} for r in ROLES.keys()}
    
    for u, st in stats.items():
        if st["total"] == 0: continue
        r = users[u]["role"]
        out_r = st["out"] / st["total"]
        night_r = st["night"] / st["total"]
        
        st["out_rate"] = out_r
        st["night_rate"] = night_r
        
        role_aggregates[r]["out_rates"].append(out_r)
        role_aggregates[r]["night_rates"].append(night_r)

    # Compute Role Means & Stdevs
    role_metrics = {}
    for r, data in role_aggregates.items():
        o_mean = statistics.mean(data["out_rates"]) if data["out_rates"] else 0
        o_std = statistics.stdev(data["out_rates"]) if len(data["out_rates"]) > 1 else 0.01
        if o_std == 0: o_std = 0.01
        
        n_mean = statistics.mean(data["night_rates"]) if data["night_rates"] else 0
        n_std = statistics.stdev(data["night_rates"]) if len(data["night_rates"]) > 1 else 0.01
        if n_std == 0: n_std = 0.01
        
        role_metrics[r] = {"o_mean": o_mean, "o_std": o_std, "n_mean": n_mean, "n_std": n_std}

    # Calculate final composite Z-score per user
    user_scores = {}
    for u, st in stats.items():
        if st["total"] == 0: 
            user_scores[u] = 0
            continue
        
        r = users[u]["role"]
        rm = role_metrics[r]
        
        z_out = (st["out_rate"] - rm["o_mean"]) / rm["o_std"]
        z_night = (st["night_rate"] - rm["n_mean"]) / rm["n_std"]
        
        # Composite score
        score = max(0, z_out) + max(0, z_night)
        user_scores[u] = score
        
    return user_scores, stats

def calc_auc(x, y):
    """
    Calculates Area Under the Curve (AUC) using simple trapezoidal integration.
    """
    # simple trapezoidal integration
    auc = 0.0
    for i in range(1, len(x)):
        auc += (x[i] - x[i-1]) * (y[i] + y[i-1]) / 2.0
    return abs(auc)

def evaluate_thresholds(user_scores, actual_malicious, num_users):
    """
    Runs threshold sweeps across user Z-scores to calculate Precision, Recall, 
    AUROC, and AUPRC. Also captures metrics for a designated fixed strict threshold.
    """
    thresholds = sorted(list(set(user_scores.values())))
    roc_points = []
    pr_points = []
    
    p_actual = len(actual_malicious)
    n_actual = num_users - p_actual
    
    FIXED_THRESHOLD = 1.8
    
    for t in thresholds:
        predicted = {u for u, score in user_scores.items() if score >= t}
        
        tp = len(predicted.intersection(actual_malicious))
        fp = len(predicted - actual_malicious)
        fn = p_actual - tp
        tn = n_actual - fp
        
        tpr = tp / p_actual if p_actual > 0 else 0
        fpr = fp / n_actual if n_actual > 0 else 0
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tpr
        
        roc_points.append((fpr, tpr))
        pr_points.append((recall, precision))
        
    # Evaluate at Fixed Strict Threshold for reporting point constraints
    predicted_fixed = {u for u, score in user_scores.items() if score >= FIXED_THRESHOLD}
    tp_f = len(predicted_fixed.intersection(actual_malicious))
    fp_f = len(predicted_fixed - actual_malicious)
    fn_f = p_actual - tp_f
    tn_f = n_actual - fp_f
    tpr_f = tp_f / p_actual if p_actual > 0 else 0
    prec_f = tp_f / (tp_f + fp_f) if (tp_f + fp_f) > 0 else 1.0
    rec_f = tpr_f
    f1_f = 2 * (prec_f * rec_f) / (prec_f + rec_f) if (prec_f + rec_f) > 0 else 0
    
    fixed_metrics = {"tp": tp_f, "fp": fp_f, "tn": tn_f, "fn": fn_f, "precision": prec_f, "recall": rec_f, "f1": f1_f, "predicted": predicted_fixed}

    # Sort for AUC calc
    roc_points.sort()
    pr_points.sort(reverse=True)
    
    fpr_list, tpr_list = [p[0] for p in roc_points], [p[1] for p in roc_points]
    rec_list, prec_list = [p[0] for p in pr_points], [p[1] for p in pr_points]
    
    auroc = calc_auc(fpr_list, tpr_list)
    auprc = calc_auc(rec_list, prec_list)
    
    return FIXED_THRESHOLD, fixed_metrics, auroc, auprc

def run_experiment(seed):
    """
    Runs a single iteration of dataset generation, behavior scoring, and compares 
    workload operations between the Baseline workflows and the Proposed workflow.
    """
    users, malicious_ids, logs = generate_dataset(seed)
    user_scores, user_stats = calculate_risk_scores(users, logs)
    
    opt_t, metrics, auroc, auprc = evaluate_thresholds(user_scores, malicious_ids, NUM_USERS)
    
    if not metrics:
        return None
        
    predicted_flagged = metrics["predicted"]
    
    # Calculate FP Rate per Role
    role_fps = {r: 0 for r in ROLES.keys()}
    role_counts = {r: 1e-5 for r in ROLES.keys()} # avoid div0
    for u in users.keys():
        r = users[u]["role"]
        if u not in malicious_ids:
            role_counts[r] += 1
            if u in predicted_flagged:
                role_fps[r] += 1
    
    role_fp_rates = {r: role_fps[r]/role_counts[r] for r in ROLES.keys()}

    total_logs = len(logs)
    
    # ---------------- BASELINES EVALUATION ----------------
    
    # Baseline A: Plaintext (Perfect Precision visually, but scans EVERYTHING)
    # Exposes all PHI logically because DLP/ML content scanners rip open every file.
    bA_exposure = total_logs
    bA_rev_minutes = total_logs * 0.05 # Fast automated scanning, but high gross compute
    
    # Baseline B: Metadata Anomaly -> Unbounded Pull
    bB_exposure = 0
    bB_escalations = 0 # No formal gated escalation board
    for u in predicted_flagged:
        bB_exposure += user_stats[u]["total"] # Pulls all records for the flagged user
        
    bB_rev_minutes = 30 + (bB_exposure * 0.5) # Time spent manually reviewing the massive dump

    # Proposed: Metadata Anomaly -> Gated Bounded Escalation
    p_exposure = 0
    p_escalations = len(predicted_flagged) # Requires 1 board approval per flagged user
    
    for u in predicted_flagged:
        # Only exposes the "anomalous" sessions bounded by metadata scoping
        anomalous_count = len([l for l in logs if l["uid"] == u and l["is_anomalous_session"]])
        p_exposure += anomalous_count
        
    p_rev_minutes = (p_escalations * 45) + (p_exposure * 1.5) # Harder to get approval, but review is highly concentrated
    
    # -------------------------------------------------------

    return {
        "detection": {
            "f1": metrics["f1"],
            "recall": metrics["recall"],
            "precision": metrics["precision"],
            "auroc": auroc,
            "auprc": auprc,
            "tp": metrics["tp"],
            "fp": metrics["fp"],
            "tn": metrics["tn"],
            "fn": metrics["fn"]
        },
        "role_fp_rates": role_fp_rates,
        "workflows": {
            "Baseline_A_Plaintext": {"exposure": bA_exposure, "escalations": 0, "rev_minutes": bA_rev_minutes},
            "Baseline_B_Unbounded": {"exposure": bB_exposure, "escalations": 0, "rev_minutes": bB_rev_minutes},
            "Proposed": {"exposure": p_exposure, "escalations": p_escalations, "rev_minutes": p_rev_minutes}
        }
    }

def run_monte_carlo(runs=30):
    """
    Executes multiple runs to derive aggregate means and standard deviations 
    across the detection performance metrics, workflow evaluations, and FP rates.
    """
    print(f"Running Exp2 Monte Carlo (N={runs})...")
    results = []
    
    for i in range(runs):
        res = run_experiment(i)
        if res: results.append(res)
        
    if not results: return {}
    
    # Aggregate
    agg = {
        "detection": {},
        "role_fp_rates": {r: {"mean": 0, "std": 0} for r in ROLES.keys()},
        "workflows": {
            "Baseline_A_Plaintext": {},
            "Baseline_B_Unbounded": {},
            "Proposed": {}
        }
    }
    
    # Det Agg
    for k in results[0]["detection"].keys():
        arr = [r["detection"][k] for r in results]
        agg["detection"][k] = {"mean": statistics.mean(arr), "std": statistics.stdev(arr) if runs > 1 else 0}
        
    # Role FP Agg
    for r in ROLES.keys():
        arr = [res["role_fp_rates"][r] for res in results]
        agg["role_fp_rates"][r] = {"mean": statistics.mean(arr), "std": statistics.stdev(arr) if runs > 1 else 0}
        
    # Flow Agg
    for w_name in agg["workflows"].keys():
        for metric in ["exposure", "escalations", "rev_minutes"]:
            arr = [r["workflows"][w_name][metric] for r in results]
            agg["workflows"][w_name][metric] = {"mean": statistics.mean(arr), "std": statistics.stdev(arr) if runs > 1 else 0}
            
    return agg


if __name__ == "__main__":
    final_output = run_monte_carlo(runs=30)
    
    os.makedirs("results", exist_ok=True)
    out_file = "results/results_exp2_advanced.json"
    with open(out_file, "w") as f:
        json.dump(final_output, f, indent=4)
        
    print(f"Done. Output saved to {out_file}")
