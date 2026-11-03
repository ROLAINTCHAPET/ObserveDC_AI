# Tests de politique (opa test /policies), exécutés en CI. Les mêmes cas sont rejoués
# contre le moteur local Python par observia/tests/test_policy.py (parité des moteurs).
package observia.guardrail_test

import rego.v1

import data.observia.guardrail

base := {
	"action_id": "restart_service",
	"params_valid": true,
	"confidence": 0.9,
	"human_approval": false,
	"target": {"known": true, "kind": "equipment", "type": "server", "criticality": "LOW", "env": "TEST", "impacted_count": 1},
	"state": {"kill_switch": false, "shadow_mode": false, "open_levels": [1, 2], "quota_exceeded": false, "lock_held": false},
	"limits": {"max_impacted_equipment": 3, "min_confidence": 0.5},
}

res(inp) := r if {
	r := guardrail.result with input as inp
}

test_nominal_level2_executes if {
	r := res(base)
	r.decision == "EXECUTE"
	r.effective_level == 2
}

test_unknown_action_refused if {
	r := res(object.union(base, {"action_id": "rm_rf"}))
	r.decision == "REFUSED"
	r.effective_level == 3
}

test_invalid_params_refused if res(object.union(base, {"params_valid": false})).decision == "REFUSED"

test_target_type_not_allowed_refused if {
	inp := object.union(base, {"target": object.union(base.target, {"type": "rack"})})
	res(inp).decision == "REFUSED"
}

test_br12_critical_prod_raises_to_level3 if {
	inp := object.union(base, {"target": object.union(base.target, {"criticality": "CRITICAL", "env": "PROD"})})
	r := res(inp)
	r.effective_level == 3
	r.decision == "PENDING_APPROVAL"
}

test_br12_non_intrusive_n1_not_raised if {
	inp := object.union(base, {
		"action_id": "open_ticket",
		"target": object.union(base.target, {"criticality": "CRITICAL", "env": "PROD"}),
	})
	res(inp).effective_level == 1
}

test_br06_blast_radius_raises_to_level3 if {
	inp := object.union(base, {"target": object.union(base.target, {"impacted_count": 4})})
	res(inp).effective_level == 3
}

test_zone_wide_target_is_level3 if {
	inp := object.union(base, {"action_id": "adjust_cooling", "target": object.union(base.target, {"kind": "zone", "type": "zone"})})
	res(inp).effective_level == 3
}

test_low_confidence_forces_level3 if res(object.union(base, {"confidence": 0.3})).effective_level == 3

test_missing_confidence_forces_level3 if res(object.remove(base, ["confidence"])).effective_level == 3

test_kill_switch_prevails if {
	inp := object.union(base, {"state": object.union(base.state, {"kill_switch": true})})
	res(inp).decision == "PENDING_APPROVAL"
}

test_level_not_open if {
	inp := object.union(base, {"state": object.union(base.state, {"open_levels": [1]})})
	res(inp).decision == "PENDING_APPROVAL"
}

test_shadow_mode if {
	inp := object.union(base, {"state": object.union(base.state, {"shadow_mode": true, "open_levels": []})})
	res(inp).decision == "SHADOW"
}

test_shadow_mode_level3_still_needs_approval if {
	inp := object.union(base, {
		"action_id": "power_cut_rack",
		"params": {},
		"target": object.union(base.target, {"type": "rack"}),
		"state": object.union(base.state, {"shadow_mode": true}),
	})
	res(inp).decision == "PENDING_APPROVAL"
}

test_quota_exceeded if {
	inp := object.union(base, {"state": object.union(base.state, {"quota_exceeded": true})})
	res(inp).decision == "PENDING_APPROVAL"
}

test_lock_held if {
	inp := object.union(base, {"state": object.union(base.state, {"lock_held": true})})
	res(inp).decision == "PENDING_APPROVAL"
}

test_human_approval_executes_level3 if {
	inp := object.union(base, {
		"action_id": "power_cut_rack",
		"human_approval": true,
		"target": object.union(base.target, {"type": "rack"}),
		"state": object.union(base.state, {"kill_switch": true}),
	})
	res(inp).decision == "EXECUTE"
}

test_human_approval_cannot_bypass_catalog if {
	res(object.union(base, {"action_id": "rm_rf", "human_approval": true})).decision == "REFUSED"
}

test_empty_input_fails_safe if res({}).decision != "EXECUTE"

test_missing_params_valid_refused if res(object.remove(base, ["params_valid"])).decision == "REFUSED"

test_missing_state_needs_approval if {
	r := res(object.remove(base, ["state"]))
	r.decision == "PENDING_APPROVAL"
	"quota d'actions automatiques atteint" in r.reasons
}
