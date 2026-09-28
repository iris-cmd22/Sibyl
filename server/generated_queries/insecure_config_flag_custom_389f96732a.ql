/**
 * @name Insecure configuration flag (generic)
 * @description Detects calls with insecure configuration flags. Parameters \
 * are injected by the run_insecure_config_flag_query tool.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.0
 * @precision medium
 * @id py/insecure-config-flag-cwe-295
 * @tags security
 *       external/cwe/cwe-295
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs

from API::CallNode call
where
  call = API::moduleImport("requests").getMember(["get", "post"]).getACall() and
  call.getKeywordParameter("verify").getAValueReachingSink().asExpr().(ImmutableLiteral).booleanValue() = false
select call, "Insecure configuration: requests.get(..., verify=false). This is vulnerable to CWE-295."
