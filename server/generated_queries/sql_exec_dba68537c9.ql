/**
 * @name SQL execution inventory
 * @description CWE-agnostic inventory of SQL execution calls, surfaced regardless of
 *              data flow. No vulnerability class is assumed: the agent decides in
 *              Validation whether untrusted input reaches this call.
 * @kind problem
 * @problem.severity recommendation
 * @security-severity 1.0
 * @id py/sql-exec-inventory
 * @tags security
 */

import python
import semmle.python.Concepts

from SqlExecution call
select call, "sql-exec"
