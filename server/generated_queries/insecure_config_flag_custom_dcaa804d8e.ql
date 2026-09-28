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
  call = API::moduleImport("requests").getMember(["get"]).getACall() and
  exists(StringLiteral s | s = call.getKeywordParameter("verify").getAValueReachingSink().asExpr() and s.getText().toLowerCase() in ["'x\" or 1=1 //'", "\"x\" or 1=1 //\""])
select call, "Insecure configuration: requests.get(..., verify=x\" or 1=1 //). This is vulnerable to CWE-295."
