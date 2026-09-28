/**
 * @name Insecure config-flag call inventory
 * @description CWE-agnostic inventory of calls passing a security-relevant keyword
 *              argument (verify=, shell=, debug=, ...) as a literal value. Structural
 *              (AST/data-flow), not name-based: no vulnerability class is assumed, the
 *              agent decides in Validation whether the literal value is insecure.
 * @kind problem
 * @problem.severity recommendation
 * @security-severity 1.0
 * @id py/insecure-config-flag-inventory
 * @tags security
 */

import python
import semmle.python.dataflow.new.DataFlow

from DataFlow::CallCfgNode call, string p
where
  p = ["verify", "shell", "autoescape", "debug", "secure", "httponly", "samesite", "check_hostname", "ssl_verify"] and
  call.getArgByName(p).asExpr() instanceof ImmutableLiteral
select call, "config-flag"
