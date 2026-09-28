/**
 * @name OS command execution with shell=True
 * @description Using shell=True with subprocess allows shell metacharacter \
 * injection, enabling OS command injection attacks.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id py/insecure-shell-true-cwe-078
 * @tags security
 *       external/cwe/cwe-078
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs

from API::CallNode call
where
  call = API::moduleImport("subprocess").getMember([
    "run", "call", "Popen", "check_call", "check_output"
  ]).getACall() and
  call.getKeywordParameter("shell")
      .getAValueReachingSink()
      .asExpr()
      .(ImmutableLiteral)
      .booleanValue() = true
select call, "This subprocess call enables shell interpretation with shell=True, which is vulnerable to command injection."
