/**
 * @name Insecure configuration flag (generic)
 * @description Detects calls with insecure configuration flags. Parameters \
 * are injected by the run_insecure_config_flag_query tool.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.0
 * @precision medium
 * @id py/insecure-config-flag-cwe-489
 * @tags security
 *       external/cwe/cwe-489
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs

from API::CallNode call
where
  call = API::moduleImport("app").getMember(["run"]).getACall() and
  call.getKeywordParameter("debug").getAValueReachingSink().asExpr().(ImmutableLiteral).booleanValue() = true
select call, "Insecure configuration: app.run(..., debug=True). This is vulnerable to CWE-489."
