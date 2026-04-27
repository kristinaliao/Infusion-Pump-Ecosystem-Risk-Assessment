#!/usr/bin/env python3
"""
Experiment Runner: Validates security hypotheses regarding network design and patching.
This module executes the three core experiments defined in the project:
1. Flat vs. Segmented Network risk comparison.
2. Comparative analysis of patching strategies (Random vs. CVSS vs. Optimized).
3. Impact of Criticality-Aware risk scoring.
"""

import random
from security_engine import AttackGraphEngine
import networkx as nx

def run_experiment_1():
    """
    Experiment 1: Flat vs Segmented Network.
    Measures the security benefit of adopting a multi-zone NIST-compliant architecture.
    """
    print("[*] Running Experiment 1: Flat vs Segmented Network...")
    results = []
    engine = AttackGraphEngine(vuln_data_path='data/vulnerability_library.json')
    engine.load_vulnerabilities()
    
    # Target common to both topologies (The ICU Infusion Pump)
    target = "pump_icu_1"
    
    for topo in ["flat", "segmented"]:
        engine.load_topology(f"topologies/{topo}.json")
        engine.decorate_nodes(scoring_mode='new')
        
        num_paths = len(list(nx.all_simple_paths(engine.network, source='attacker', target=target)))
        total_risk = engine.calculate_total_network_risk(target)
        highest_risk = engine.calculate_highest_path_risk(target)
        
        results.append({
            "topology": topo.capitalize(),
            "paths": num_paths,
            "total_risk": total_risk,
            "highest_risk": highest_risk
        })

    # Save results to disk
    with open("experiment_1_results.txt", "w") as f:
        f.write("Experiment 1: Flat vs Segmented Network\n")
        f.write("-" * 40 + "\n")
        for res in results:
            f.write(f"Topology: {res['topology']}\n")
            f.write(f"  Number of Attack Paths: {res['paths']}\n")
            f.write(f"  Total Network Risk: {res['total_risk']:.2f}\n")
            f.write(f"  Highest Path Risk: {res['highest_risk']:.2f}\n\n")
    
    return results

def run_experiment_2():
    """
    Experiment 2: Patching Strategies.
    Compares Random patching, Highest-CVSS patching, and the Risk-Reduction Optimizer.
    """
    print("[*] Running Experiment 2: Patching Strategies...")
    engine = AttackGraphEngine(vuln_data_path='data/vulnerability_library.json')
    engine.load_vulnerabilities()
    engine.load_topology("topologies/flat.json")
    target = "pump_icu_1"
    
    # Calculate initial baseline risk
    engine.decorate_nodes(scoring_mode='new')
    base_risk = engine.calculate_total_network_risk(target)
    
    def get_residual_risk(nodes_to_patch):
        """Helper to reload topo and simulate patching a specific set of nodes."""
        engine.load_topology("topologies/flat.json")
        engine.decorate_nodes(scoring_mode='new')
        for node in nodes_to_patch:
            engine.patch_node(node)
        return engine.calculate_total_network_risk(target)

    # Define nodes eligible for patching (excludes attacker/routers)
    eligible_nodes = [node for node in engine.network.nodes() if node != 'attacker' and engine.network.nodes[node].get('profile') != 'Router']
    num_to_patch = 3
    
    # Strategy A: Random Selection
    random_patch = random.sample(eligible_nodes, num_to_patch)
    risk_a = get_residual_risk(random_patch)
    
    # Strategy B: Highest CVSS Priority (Industry Standard)
    engine.load_topology("topologies/flat.json")
    engine.decorate_nodes(scoring_mode='old') # Uses CVSS-only for prioritization
    node_risks = [(node, engine.network.nodes[node]['cumulative_risk']) for node in eligible_nodes]
    node_risks.sort(key=lambda x: x[1], reverse=True)
    cvss_patch = [n[0] for n in node_risks[:num_to_patch]]
    risk_b = get_residual_risk(cvss_patch)
    
    # Strategy C: Risk-Reduction Optimizer (Proposed Approach)
    engine.load_topology("topologies/flat.json")
    engine.decorate_nodes(scoring_mode='new')
    patch_impacts = []
    for node in eligible_nodes:
        original_vulns = engine.network.nodes[node]['vulnerabilities']
        original_risk = engine.network.nodes[node]['cumulative_risk']
        engine.patch_node(node)
        reduction = base_risk - engine.calculate_total_network_risk(target)
        patch_impacts.append((node, reduction))
        # Restore state for next iteration of sensitivity analysis
        engine.network.nodes[node]['vulnerabilities'] = original_vulns
        engine.network.nodes[node]['cumulative_risk'] = original_risk
    
    patch_impacts.sort(key=lambda x: x[1], reverse=True)
    optimized_patch = [n[0] for n in patch_impacts[:num_to_patch]]
    risk_c = get_residual_risk(optimized_patch)
    
    # Save results to disk
    with open("experiment_2_results.txt", "w") as f:
        f.write("Experiment 2: Patching Strategies (Top 3 nodes)\n")
        f.write("-" * 40 + "\n")
        f.write(f"Initial Risk: {base_risk:.2f}\n")
        f.write(f"Strategy A (Random) Residual Risk: {risk_a:.2f}\n")
        f.write(f"Strategy B (Highest CVSS) Residual Risk: {risk_b:.2f}\n")
        f.write(f"Strategy C (Optimizer) Residual Risk: {risk_c:.2f}\n")
    
    return {"base": base_risk, "A": risk_a, "B": risk_b, "C": risk_c}

def run_experiment_3():
    """
    Experiment 3: Criticality-Aware Scoring.
    Demonstrates how the clinical criticality multiplier re-prioritizes infusion pumps
    over more vulnerable but less critical enterprise systems.
    """
    print("[*] Running Experiment 3: Criticality-Aware Scoring...")
    engine = AttackGraphEngine(vuln_data_path='data/vulnerability_library.json')
    engine.load_vulnerabilities()
    engine.load_topology("topologies/segmented.json")
    
    # Select representative nodes from the pump ecosystem
    representative_nodes = ["admin_pc_1", "med_gw_1", "pump_icu_3", "pump_icu_1"]
    
    results = {}
    for mode in ['old', 'new']:
        engine.decorate_nodes(scoring_mode=mode)
        node_risks = [(node, engine.network.nodes[node].get('profile'), engine.network.nodes[node]['cumulative_risk']) for node in representative_nodes]
        node_risks.sort(key=lambda x: x[2], reverse=True)
        results[mode] = node_risks
    
    # Save results to disk
    with open("experiment_3_results.txt", "w") as f:
        f.write("Experiment 3: Criticality-Aware Scoring\n")
        f.write("-" * 40 + "\n")
        f.write("Mode: Old (CVSS Only)\n")
        for node, profile, risk in results['old']:
            f.write(f"  {node} ({profile}): {risk:.2f}\n")
        f.write("\nMode: New (CVSS x Criticality x Exposure)\n")
        for node, profile, risk in results['new']:
            f.write(f"  {node} ({profile}): {risk:.2f}\n")
            
    return results

def generate_table_data():
    """
    Generates structured data for paper tables.
    """
    print("[*] Generating Table Data...")
    engine = AttackGraphEngine(vuln_data_path='data/vulnerability_library.json')
    engine.load_vulnerabilities()
    
    with open("table_data.txt", "w") as f:        
        # Table 1: Best Mitigations
        target = "pump_icu_1"
        engine.load_topology("topologies/flat.json")
        engine.decorate_nodes(scoring_mode='new')
        base_risk = engine.calculate_total_network_risk(target)
        
        patch_impacts = []
        for node in engine.network.nodes():
            if node == 'attacker' or engine.network.nodes[node].get('profile') == 'Router': continue
            original_vulns = engine.network.nodes[node]['vulnerabilities']
            original_risk = engine.network.nodes[node]['cumulative_risk']
            engine.patch_node(node)
            reduction = ((base_risk - engine.calculate_total_network_risk(target)) / base_risk) * 100
            patch_impacts.append((f"Patch {node}", reduction))
            engine.network.nodes[node]['vulnerabilities'] = original_vulns
            engine.network.nodes[node]['cumulative_risk'] = original_risk
            
        patch_impacts.sort(key=lambda x: x[1], reverse=True)
        
        f.write("Table 1: Best Mitigations\n")
        f.write("Action\tRisk Reduction\n")
        for action, reduction in patch_impacts[:5]:
            f.write(f"{action}\t{reduction:.1f}%\n")
        f.write("\n")
        
        # Table 2: Segmentation Comparison
        f.write("Table 2: Segmentation Comparison\n")
        f.write("Network Design\tPaths\tTotal Risk\n")
        for topo in ["flat", "segmented"]:
            engine.load_topology(f"topologies/{topo}.json")
            engine.decorate_nodes(scoring_mode='new')
            num_paths = len(list(nx.all_simple_paths(engine.network, source='attacker', target=target)))
            total_risk = engine.calculate_total_network_risk(target)
            f.write(f"{topo.capitalize()}\t{num_paths}\t{total_risk:.2f}\n")

if __name__ == "__main__":
    run_experiment_1()
    run_experiment_2()
    run_experiment_3()
    generate_table_data()
    print("[+] All experiments complete and results saved.")
