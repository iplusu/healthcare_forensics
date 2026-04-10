"""
exp3_integrity.py

Experiment 3: End-to-End Evidentiary Overhead & Tamper Detection

This script evaluates the systemic overhead (latency and storage) and the tamper-detection 
capabilities of various architectural models for maintaining the integrity of clinical audit logs.

The models evaluated are:
1. BaselineSystem: Standard stateless log ingestion.
2. HashSystem: Ingestion with individual object hashing.
3. ChainSystem: Hashing with chronological chaining (hash chain).
4. FullWorkflowSystem: Comprehensive binding of logs, custody, and analysis chains 
   via a unified manifest signature.
   
The experiment injects simulated tamper scenarios (e.g., modifications, deletions, reordering) 
both in-system (caught via Audit Replay) and in-transit (caught via Handoff Verification).
"""

import time
import hashlib
import json
import os
import copy
import random

# Experiment configurations
BATCH_SIZES = [1000, 10000, 50000]

def generate_log_events(n):
    """
    Generates a deterministic sequence of simulated log events.
    """
    events = []
    base_time = 1700000000.0
    for i in range(n):
        events.append({
            "event_id": f"EVT-{i:07d}-{random.randint(1000, 9999)}",
            "timestamp": base_time + i,
            "user_id": f"U{random.randint(100, 999)}",
            "action": random.choice(["READ_PATIENT", "WRITE_NOTES", "EXPORT_DATA", "LOGIN"]),
            "resource": f"P-{random.randint(1000, 9999)}"
        })
    return events


class BaselineSystem:
    """
    Standard Baseline System representing typical logging without cryptographic integrity constraints.
    """
    def __init__(self):
        self.logs = []
    
    def ingest(self, events):
        start = time.perf_counter()
        for e in events:
            self.logs.append(json.dumps(e, separators=(",", ":")))
        return time.perf_counter() - start
        
    def storage_bytes(self):
        return sum(len(l.encode('utf-8')) for l in self.logs)

    def query_events(self, target_ids):
        start = time.perf_counter()
        found = 0
        for l_str in self.logs:
            for tid in target_ids:
                if tid in l_str:
                    found += 1
        return time.perf_counter() - start

    def finalize_ingestion(self):
        pass

    def generate_package(self):
        start = time.perf_counter()
        pkg = {"logs": self.logs}
        pkg_str = json.dumps(pkg)
        return (time.perf_counter() - start), pkg_str

    def verify_handoff(self, pkg_str):
        start = time.perf_counter()
        return time.perf_counter() - start, True

    def audit_replay(self):
        start = time.perf_counter()
        return time.perf_counter() - start, True


class HashSystem(BaselineSystem):
    """
    System that hashes each individual log entry for basic integrity verification.
    """
    def ingest(self, events):
        start = time.perf_counter()
        for e in events:
            log_str = json.dumps(e, separators=(",", ":"))
            log_hash = hashlib.sha256(log_str.encode('utf-8')).hexdigest()
            self.logs.append(json.dumps({"log": log_str, "hash": log_hash}, separators=(",", ":")))
        return time.perf_counter() - start

    def audit_replay(self):
        start = time.perf_counter()
        for l_str in self.logs:
            obj = json.loads(l_str)
            if hashlib.sha256(obj["log"].encode('utf-8')).hexdigest() != obj.get("hash"):
                return time.perf_counter() - start, False
        return time.perf_counter() - start, True


class ChainSystem(HashSystem):
    """
    System that uses a continuous cryptographic hash chain across chronological log events.
    """
    def ingest(self, events):
        start = time.perf_counter()
        prev_hash = "0" * 64
        if self.logs:
            prev_hash = json.loads(self.logs[-1])["hash"]

        for e in events:
            log_str = json.dumps(e, separators=(",", ":"))
            content_to_hash = log_str + prev_hash
            log_hash = hashlib.sha256(content_to_hash.encode('utf-8')).hexdigest()
            self.logs.append(json.dumps({
                "log": log_str, 
                "prev_hash": prev_hash, 
                "hash": log_hash
            }, separators=(",", ":")))
            prev_hash = log_hash
        return time.perf_counter() - start

    def audit_replay(self):
        start = time.perf_counter()
        prev_hash = "0" * 64
        for l_str in self.logs:
            obj = json.loads(l_str)
            if obj.get("prev_hash") != prev_hash:
                return time.perf_counter() - start, False
            content_to_hash = obj["log"] + prev_hash
            if hashlib.sha256(content_to_hash.encode('utf-8')).hexdigest() != obj.get("hash"):
                return time.perf_counter() - start, False
            prev_hash = obj["hash"]
        return time.perf_counter() - start, True


class FullWorkflowSystem(ChainSystem):
    """
    Proposed Architecture (Full Workflow System).
    Binds the primary logs with metadata (custody, analysis) using a unified manifest.
    """
    def __init__(self):
        super().__init__()
        self.custody_log = []
        self.manifest = None
        self.analysis_log = []
    
    def log_custody(self, event_type, actor):
        prev_hash = "0" * 64
        if self.custody_log:
            prev_hash = json.loads(self.custody_log[-1])["hash"]

        c_event = {"event": event_type, "actor": actor, "ts": 1700000000.0}
        c_str = json.dumps(c_event, separators=(",", ":"))
        content_to_hash = c_str + prev_hash
        self.custody_log.append(json.dumps({
            "log": c_str,
            "prev_hash": prev_hash,
            "hash": hashlib.sha256(content_to_hash.encode('utf-8')).hexdigest()
        }, separators=(",", ":")))
        
    def _create_manifest(self, current_logs, current_custody, current_analysis):
        """
        Creates a bundled cryptographic manifest summarizing the current state of 
        the logs, custody chain, and analysis events.
        """
        last_log_hash = json.loads(current_logs[-1])["hash"] if current_logs else "0" * 64
        last_custody_hash = json.loads(current_custody[-1])["hash"] if current_custody else "0" * 64
        last_analysis_hash = json.loads(current_analysis[-1])["hash"] if current_analysis else "0" * 64
        
        manifest_data = f"{last_log_hash}|{last_custody_hash}|{last_analysis_hash}"
        return {
            "root_log_hash": last_log_hash,
            "root_custody_hash": last_custody_hash,
            "root_analysis_hash": last_analysis_hash,
            "manifest_signature": hashlib.sha256(manifest_data.encode('utf-8')).hexdigest()
        }

    def finalize_ingestion(self):
        """
        Completes the internal state, modeling the transition between ingestion and analytics.
        Sets up the internal tracking manifest.
        """
        if not self.custody_log:
            self.log_custody("INGEST_COMPLETE", "SYSTEM")
            
        if not self.analysis_log:
            a_prev = "0" * 64
            for _ in range(10): 
                ev_str = "ANALYSIS_PHASE_COMPLETE"
                ev_hash = hashlib.sha256((ev_str + a_prev).encode('utf-8')).hexdigest()
                self.analysis_log.append(json.dumps({
                    "log": ev_str,
                    "prev_hash": a_prev,
                    "hash": ev_hash
                }, separators=(",", ":")))
                a_prev = ev_hash
                
        # Update manifest to reflect stable bound state
        self.manifest = self._create_manifest(self.logs, self.custody_log, self.analysis_log)

    def generate_package(self):
        """
        Generates an immutable handoff package (an independent serialized record).
        """
        start = time.perf_counter()
        
        # Branch the custody chain temporarily for packaging
        pkg_custody = list(self.custody_log)
        
        # Append HANDOFF event
        prev_hash = json.loads(pkg_custody[-1])["hash"] if pkg_custody else "0" * 64
        c_event = {"event": "HANDOFF_START", "actor": "SYSTEM", "ts": 1700000000.0}
        c_str = json.dumps(c_event, separators=(",", ":"))
        content_to_hash = c_str + prev_hash
        pkg_custody.append(json.dumps({
            "log": c_str,
            "prev_hash": prev_hash,
            "hash": hashlib.sha256(content_to_hash.encode('utf-8')).hexdigest()
        }, separators=(",", ":")))

        pkg_manifest = self._create_manifest(self.logs, pkg_custody, self.analysis_log)
        
        pkg = {
            "logs": list(self.logs),
            "custody": pkg_custody,
            "manifest": pkg_manifest,
            "analysis": list(self.analysis_log)
        }
        
        pkg_str = json.dumps(pkg)
        return (time.perf_counter() - start), pkg_str

    def _verify_chain(self, chain_list):
        if not chain_list: return True, "0" * 64
        prev_hash = "0" * 64
        for l_str in chain_list:
            obj = json.loads(l_str)
            if obj.get("prev_hash") != prev_hash:
                return False, prev_hash
            content_to_hash = obj["log"] + prev_hash
            if hashlib.sha256(content_to_hash.encode('utf-8')).hexdigest() != obj.get("hash"):
                return False, prev_hash
            prev_hash = obj["hash"]
        return True, prev_hash

    def verify_handoff(self, pkg_str):
        """
        Independent verification of an exported package. 
        Detects tampering during transit.
        """
        start = time.perf_counter()
        data = json.loads(pkg_str)
        m = data.get("manifest")
        if not m:
            return time.perf_counter() - start, False
            
        logs_valid, root_log_hash = self._verify_chain(data.get("logs", []))
        if not logs_valid or root_log_hash != m.get("root_log_hash"):
            return time.perf_counter() - start, False

        custody_valid, root_custody_hash = self._verify_chain(data.get("custody", []))
        if not custody_valid or root_custody_hash != m.get("root_custody_hash"):
            return time.perf_counter() - start, False

        analysis_valid, root_analysis_hash = self._verify_chain(data.get("analysis", []))
        if not analysis_valid or root_analysis_hash != m.get("root_analysis_hash"):
            return time.perf_counter() - start, False

        expected_sig = hashlib.sha256(
            f'{m["root_log_hash"]}|{m["root_custody_hash"]}|{m["root_analysis_hash"]}'.encode('utf-8')
        ).hexdigest()
        
        if m["manifest_signature"] != expected_sig:
            return time.perf_counter() - start, False
            
        return time.perf_counter() - start, True

    def audit_replay(self):
        """
        Internal system audit checking the integrity of locally stored objects.
        Detects insider/system tampering.
        """
        start = time.perf_counter()
        
        valid, l_root = self._verify_chain(self.logs)
        if not valid: return time.perf_counter() - start, False
        
        valid, c_root = self._verify_chain(self.custody_log)
        if not valid: return time.perf_counter() - start, False

        valid, a_root = self._verify_chain(self.analysis_log)
        if not valid: return time.perf_counter() - start, False
            
        if self.manifest:
            m = self.manifest
            expected_sig = hashlib.sha256(
                f'{m["root_log_hash"]}|{m["root_custody_hash"]}|{m["root_analysis_hash"]}'.encode('utf-8')
            ).hexdigest()
            if m.get("manifest_signature") != expected_sig:
                return time.perf_counter() - start, False
            if l_root != m.get("root_log_hash") or c_root != m.get("root_custody_hash") or a_root != m.get("root_analysis_hash"):
                return time.perf_counter() - start, False
            
        return time.perf_counter() - start, True
        
    def storage_bytes(self):
        sz = super().storage_bytes()
        sz += sum(len(l.encode('utf-8')) for l in self.custody_log)
        sz += sum(len(l.encode('utf-8')) for l in self.analysis_log)
        if self.manifest:
            sz += len(json.dumps(self.manifest).encode('utf-8'))
        return sz


# =============================================================================
# Tampering Simulation Functions
# =============================================================================

def apply_tamper(system, scenario, is_baseline=False):
    """
    Injects anomalies into the internal state representing Live System compromise.
    """
    sys_copy = system.__class__()
    sys_copy.logs = list(system.logs)
    if hasattr(system, 'custody_log'): sys_copy.custody_log = list(system.custody_log)
    if hasattr(system, 'analysis_log'): sys_copy.analysis_log = list(system.analysis_log)
    if hasattr(system, 'manifest') and system.manifest is not None:
        sys_copy.manifest = copy.deepcopy(system.manifest)
        
    if not sys_copy.logs: return sys_copy
    mid_idx = len(sys_copy.logs) // 2
    
    if scenario == "object_modify":
        if is_baseline:
            obj = json.loads(sys_copy.logs[mid_idx])
            obj["resource"] = "MODIFIED"
            sys_copy.logs[mid_idx] = json.dumps(obj)
        else:
            obj = json.loads(sys_copy.logs[mid_idx])
            inner = json.loads(obj["log"])
            inner["resource"] = "MODIFIED"
            obj["log"] = json.dumps(inner, separators=(",", ":"))
            sys_copy.logs[mid_idx] = json.dumps(obj, separators=(",", ":"))
            
    elif scenario == "event_delete":
        sys_copy.logs.pop(mid_idx)
        
    elif scenario == "reorder":
        if mid_idx + 1 < len(sys_copy.logs):
            sys_copy.logs[mid_idx], sys_copy.logs[mid_idx+1] = sys_copy.logs[mid_idx+1], sys_copy.logs[mid_idx]
            
    elif scenario == "manifest_mismatch":
        if hasattr(sys_copy, "manifest") and sys_copy.manifest:
            sys_copy.manifest["manifest_signature"] = "BAD_SIG"
            
    elif scenario == "insertion":
        if is_baseline:
            sys_copy.logs.insert(mid_idx, json.dumps({"added": "fake"}))
        else:
            sys_copy.logs.insert(mid_idx, json.dumps({"log": '{"added":"fake"}', "hash": "bad", "prev_hash": "bad"}))

    elif scenario == "custody_delete":
        if hasattr(sys_copy, "custody_log") and len(sys_copy.custody_log) > 0:
            sys_copy.custody_log.pop(len(sys_copy.custody_log) // 2)

    return sys_copy

def apply_tamper_to_package_str(pkg_str, scenario, is_baseline=False):
    """
    Injects anomalies into a serialized handoff package mimicking transit manipulation.
    """
    pkg = json.loads(pkg_str)
    logs = pkg.get("logs", [])
    
    if not logs:
        return pkg_str
        
    mid_idx = len(logs) // 2
    
    if scenario == "object_modify":
        if is_baseline:
            obj = json.loads(logs[mid_idx])
            obj["resource"] = "MODIFIED"
            logs[mid_idx] = json.dumps(obj)
        else:
            obj = json.loads(logs[mid_idx])
            inner = json.loads(obj["log"])
            inner["resource"] = "MODIFIED"
            obj["log"] = json.dumps(inner, separators=(",", ":"))
            logs[mid_idx] = json.dumps(obj, separators=(",", ":"))
            
    elif scenario == "event_delete":
        if mid_idx < len(logs):
            logs.pop(mid_idx)
        
    elif scenario == "reorder":
        if mid_idx + 1 < len(logs):
            logs[mid_idx], logs[mid_idx+1] = logs[mid_idx+1], logs[mid_idx]
            
    elif scenario == "manifest_mismatch":
        if "manifest" in pkg and pkg["manifest"]:
            pkg["manifest"]["manifest_signature"] = "BAD_SIG"
            
    elif scenario == "insertion":
        if is_baseline:
            logs.insert(mid_idx, json.dumps({"added": "fake"}))
        else:
            logs.insert(mid_idx, json.dumps({"log": '{"added":"fake"}', "hash": "bad", "prev_hash": "bad"}))

    elif scenario == "custody_delete":
        if "custody" in pkg and len(pkg["custody"]) > 0:
            pkg["custody"].pop(len(pkg["custody"]) // 2)

    return json.dumps(pkg)


# =============================================================================
# Main Experiment Execution
# =============================================================================

def run_experiments():
    print("--- Experiment 3: End-to-End Evidentiary Overhead & Tamper Detection ---")
    
    # Global seed to ensure repeatability between runs
    random.seed(42)  
    results = {"batches": {}}
    tamper_scenarios = [
        "object_modify", "event_delete", "reorder", 
        "insertion", "manifest_mismatch", "custody_delete"
    ]

    for batch_size in BATCH_SIZES:
        print(f"\nEvaluating Batch Size: {batch_size} events")
        events = generate_log_events(batch_size)
        
        # Sample isolated query targets maintaining consistent RNG state 
        rng_state = random.getstate()
        random.seed(42)  
        targets = [e["event_id"] for e in random.sample(events, min(10, len(events)))]
        random.setstate(rng_state) 
        
        batch_results = {}
        models = {
            "Baseline": BaselineSystem,
            "ObjectHash": HashSystem,
            "CustodyChain": ChainSystem,
            "FullWorkflow": FullWorkflowSystem
        }
        
        base_storage = 0
        
        for name, cls in models.items():
            sys = cls()
            
            # --- 1. Ingestion Phase ---
            ingest_ms = sys.ingest(events) * 1000
            sys.finalize_ingestion() 
            
            # --- 2. Packaging / Transit Phase ---
            pkg_gen_ms, pkg_str = sys.generate_package()
            pkg_gen_ms *= 1000

            # Storage Metrics Calculation
            sz_bytes = sys.storage_bytes()
            if name == "Baseline":
                base_storage = sz_bytes
            storage_bloat = ((sz_bytes - base_storage) / base_storage * 100) if base_storage else 0
                
            query_ms = sys.query_events(targets) * 1000
            
            # --- 3. Verification Phase ---
            verify_handoff_ms, _ = sys.verify_handoff(pkg_str)
            verify_handoff_ms *= 1000
            
            audit_ms, valid_audit = sys.audit_replay()
            audit_ms *= 1000
            
            # --- Tamper Detection Simulation ---
            detection_rates_audit = {}
            detection_rates_handoff = {}
            
            for t in tamper_scenarios:
                # Basic models do not support advanced fields tampering 
                if t in ["manifest_mismatch", "custody_delete"] and name != "FullWorkflow":
                    continue
                    
                # Audit Replay (Insider Tampering)
                tampered_sys = apply_tamper(sys, t, is_baseline=(name=="Baseline"))
                _, is_valid_audit = tampered_sys.audit_replay()
                detection_rates_audit[t] = not is_valid_audit

                # transit Handoff (Network Tampering)
                tampered_pkg_str = apply_tamper_to_package_str(pkg_str, t, is_baseline=(name=="Baseline"))
                _, is_valid_handoff = sys.verify_handoff(tampered_pkg_str)
                detection_rates_handoff[t] = not is_valid_handoff

            # Aggregating Detection Efficacy
            audit_caught = sum(detection_rates_audit.values())
            audit_total = len(detection_rates_audit)
            handoff_caught = sum(detection_rates_handoff.values())
            handoff_total = len(detection_rates_handoff)

            # Record results mapping to JSON structure
            batch_results[name] = {
                "ingest_latency_ms": round(ingest_ms, 2),
                "storage_bytes": sz_bytes,
                "storage_bloat_pct": round(storage_bloat, 2),
                "query_latency_ms": round(query_ms, 2),
                "pkg_generation_ms": round(pkg_gen_ms, 2),
                "verify_handoff_ms": round(verify_handoff_ms, 2),
                "audit_replay_ms": round(audit_ms, 2),
                "tamper_detection_audit": detection_rates_audit,
                "tamper_detection_handoff": detection_rates_handoff,
                "audit_detection_summary": f"{audit_caught}/{audit_total}",
                "handoff_detection_summary": f"{handoff_caught}/{handoff_total}"
            }
            
            print(f"  {name}: {round(ingest_ms, 2)}ms ingest, {round(storage_bloat, 2)}% bloat. "
                  f"Audit Det: {audit_caught}/{audit_total}, Handoff Det: {handoff_caught}/{handoff_total}")
            
        results["batches"][str(batch_size)] = batch_results

    # Output generation
    os.makedirs("results", exist_ok=True)
    with open("results/results_exp3.json", "w") as f:
        json.dump(results, f, indent=4)
    print("\nExperiment 3 results successfully saved to results/results_exp3.json")

if __name__ == "__main__":
    run_experiments()
