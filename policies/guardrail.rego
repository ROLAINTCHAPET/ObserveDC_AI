# Politique du garde-fou (FR-12, SAD §9.2). Évaluée hors de l'agent ; requête :
#   POST /v1/data/observia/guardrail/result  {"input": {...}}
#
# Entrée (construite par guardrail/service.py à partir de la base, jamais par l'agent) :
#   action_id, params_valid, confidence, human_approval,
#   target: {known, kind (equipment|zone|site), type, criticality, env, impacted_count},
#   state:  {kill_switch, shadow_mode, open_levels, quota_exceeded, lock_held},
#   limits: {max_impacted_equipment, min_confidence}
#
# Propriétés garanties : l'agent ne peut ni inventer une action (catalogue fermé) ni abaisser
# un niveau ; le kill switch prévaut ; toute entrée incomplète mène à PENDING_APPROVAL.
# Champ absent ⇒ condition de sûreté considérée comme non remplie (« not x == true »,
# car « x != true » est indéfini, donc faux, quand x manque).
package observia.guardrail

import rego.v1

action := data.catalog[input.action_id]

in_catalog if action

# --- Refus (catalogue fermé, FR-11) -------------------------------------------

type_allowed if "*" in action.allowed_targets.types

type_allowed if input.target.type in action.allowed_targets.types

target_allowed if {
	input.target.known == true
	type_allowed
	input.target.env in action.allowed_targets.env
}

refusal_reasons contains "action hors catalogue" if not in_catalog

refusal_reasons contains "paramètres invalides" if not input.params_valid == true

refusal_reasons contains "cible inconnue ou non autorisée pour cette action" if {
	in_catalog
	not target_allowed
}

refused if count(refusal_reasons) > 0

# --- Niveau effectif (BR-01, BR-06, BR-12) : max des niveaux candidats -----------

level_candidates contains action.base_level if in_catalog

level_candidates contains 3 if not in_catalog

# BR-12 : cible critique de production
level_candidates contains 3 if {
	input.target.criticality in {"HIGH", "CRITICAL"}
	input.target.env == "PROD"
	not action.non_intrusive
}

# BR-06 : périmètre d'impact
level_candidates contains 3 if input.target.impacted_count > input.limits.max_impacted_equipment

level_candidates contains 3 if input.target.kind != "equipment"

# UC-02 : confiance basse ou absente → niveau 3 forcé
confidence_ok if {
	is_number(input.confidence)
	is_number(input.limits.min_confidence)
	input.confidence >= input.limits.min_confidence
}

level_candidates contains 3 if not confidence_ok

effective_level := max(level_candidates)

# --- Motifs de validation humaine ---------------------------------------------

approval_reasons contains "kill switch actif : autonomie suspendue" if input.state.kill_switch == true

approval_reasons contains "niveau 3 : validation humaine obligatoire" if effective_level == 3

level_open if effective_level in input.state.open_levels

approval_reasons contains "niveau non ouvert à l'autonomie" if {
	not input.state.shadow_mode == true
	not level_open
}

approval_reasons contains "quota d'actions automatiques atteint" if not input.state.quota_exceeded == false

approval_reasons contains "action déjà en cours sur la cible" if not input.state.lock_held == false

auto_allowed if {
	not refused
	not input.human_approval == true
	count(approval_reasons) == 0
}

# --- Décision -----------------------------------------------------------------

default decision := "PENDING_APPROVAL"

decision := "REFUSED" if refused

# Validation humaine authentifiée : réévaluée au moment de l'approbation (SAD §9.4)
decision := "EXECUTE" if {
	not refused
	input.human_approval == true
	input.state.lock_held == false
}

decision := "SHADOW" if {
	auto_allowed
	input.state.shadow_mode == true
}

decision := "EXECUTE" if {
	auto_allowed
	input.state.shadow_mode == false
}

result := {
	"decision": decision,
	"effective_level": effective_level,
	"reasons": sort(refusal_reasons | approval_reasons),
}
