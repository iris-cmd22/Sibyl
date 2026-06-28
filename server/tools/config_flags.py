"""Insecure-configuration-flag detection (point detection, not taint).

The dedicated check_insecure_* tools for common cases are registered by the
registry; this module exposes the generic parametrized tool for custom patterns.
"""
from __future__ import annotations

import json

from server.core.executor import render_and_analyze
from server.core.template import normalize_cwe, is_valid_name
from server.knowledge.store import CWE_REFERENCE
from server.transport.mcp_instance import mcp


# Obiettivo: rilevare CONFIGURAZIONI INSICURE generiche, cioè chiamate a una funzione
#            con un parametro impostato a un valore pericoloso (es. requests.get(verify=False)).
# Input:    db_path = database; module = modulo (es. "requests"); functions = lista di
#           funzioni; param_name = parametro (es. "verify"); insecure_value = valore
#           pericoloso (es. "false"); cwe = classe.
# Output:   stringa JSON con i finding; JSON "error" se gli identificatori non sono validi.
# Come realizzato: valida gli input, costruisce dinamicamente le condizioni CodeQL
#            (catena del modulo + confronto del parametro), riempie il template generico,
#            salva la query ed esegue analyze_with_query.
@mcp.tool()
def run_insecure_config_flag_query(
    db_path: str,
    module: str,
    functions: list[str],
    param_name: str,
    insecure_value: str,
    cwe: str = "",
) -> str:
    """Detect insecure configuration flags using a generic parametrized template.

    This tool allows you to search for calls to specific functions with insecure
    keyword arguments (e.g., verify=False, shell=True, autoescape=False).
    Use this for custom patterns not covered by the built-in check_insecure_* tools.

    Args:
        db_path: Path returned by create_codeql_database.
        module: Python module name (e.g., "requests", "subprocess", "jinja2").
        functions: List of function names to check (e.g., ["get", "post", "run"]).
        param_name: The keyword parameter name (e.g., "verify", "shell", "autoescape").
        insecure_value: The insecure value as a string (e.g., "false", "true", "none").
        cwe: Vulnerability class, e.g. "CWE-295"; stamped into the evidence.
    """
    # Validate inputs
    if not all(is_valid_name(n) for n in functions):
        return json.dumps({"error": "invalid function names (must be identifiers)"})
    if not is_valid_name(param_name):
        return json.dumps({"error": "param_name must be an identifier"})
    if not is_valid_name(module):
        return json.dumps({"error": "module must be an identifier"})

    cwe_id = normalize_cwe(cwe)[0]

    # Build the MODULE_MEMBER_CHAIN and PARAM_CONDITION for the template
    func_list = ", ".join(f'"{f}"' for f in functions)
    module_chain = (
        f'call = API::moduleImport("{module}").getMember([{func_list}]).getACall()'
    )

    # Check if value is boolean or string
    if insecure_value.lower() in ["true", "false"]:
        param_condition = (
            f'call.getKeywordParameter("{param_name}")'
            f'.getAValueReachingSink().asExpr().(ImmutableLiteral)'
            f'.booleanValue() = {insecure_value.lower()}'
        )
    else:
        # String comparison
        param_condition = (
            f'exists(StringLiteral s | s = call.getKeywordParameter("{param_name}")'
            f'.getAValueReachingSink().asExpr() and '
            f's.getText().toLowerCase() in ["\'{insecure_value.lower()}\'", '
            f'"\\\"{insecure_value.lower()}\\\""])'
        )

    message = (
        f"Insecure configuration: {module}.{functions[0]}(..., {param_name}={insecure_value}). "
        f"This is vulnerable to {cwe_id or 'security issues'}."
    )

    ref = CWE_REFERENCE.get(cwe_id, {}) if cwe_id else {}
    return render_and_analyze(
        db_path, "insecure_config_flag_generic.ql.tmpl",
        {
            "{{MODULE_MEMBER_CHAIN}}": module_chain,
            "{{PARAM_CONDITION}}": param_condition,
            "{{MESSAGE}}": message,
        },
        out_prefix="insecure_config_flag_custom", cwe=cwe,
        extra={
            "template": "insecure_config_flag_generic",
            "cwe": cwe_id,
            "cwe_name": ref.get("name"),
            "standard_remediation": ref.get("remediation"),
            "module": module,
            "functions": functions,
            "param_name": param_name,
            "insecure_value": insecure_value,
        },
    )
