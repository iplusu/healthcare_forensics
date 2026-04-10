# Forensic Investigation Simulations (FSI DI)

This repository contains simulation and evaluation code for studying the trade-offs in clinical audit log forensics across three distinct workflows:

1. **Experiment 1 (Ransomware Data Exfiltration)**: Evaluates a metadata-driven investigation bounded-escalation model against traditional bulk acquisition forms. Tests the trade-offs between Exfiltration Recall and Collateral PHI Exposure.
2. **Experiment 2 (Insider Threat Snooping)**: Simulates diverse clinical behavior to assess anomaly detection reliability versus reviewer overhead (measured in manual triage hours).
3. **Experiment 3 (Evidentiary Overhead & Integrity)**: Measures End-to-End processing latency overhead and tamper-detection coverage across baseline, ObjectHash, CustodyChain, and FullWorkflow logging architectures.

## Prerequisites

- Python 3.8+
- Required packages (see `requirements.txt`)

To install the prerequisites, run:
```bash
pip install -r requirements.txt
```

## Running the Experiments

To execute all simulations and auto-generate the corresponding visualization plots in one step, simply run:

```bash
python run_all.py
```

This orchestration script will systematically run all `exp*.py` simulators, generating JSON result payloads inside the locally ignored `results/` directory. Next, it triggers the `generate_visuals_exp*.py` scripts to parse those results and produce publication-ready `.png` diagrams mapped to each experiment inside the `figures/` directory.

### Individual Execution
If you prefer running components individually (for instance, adjusting parameters for one experiment):
1. Run target simulation (e.g., `python exp3_integrity.py`)
2. Run target visualizer (e.g., `python generate_visuals_exp3.py`)

## License

This project is open-sourced under the MIT License. See the [LICENSE](LICENSE) file for details.
