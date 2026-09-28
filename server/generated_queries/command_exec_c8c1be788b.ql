/**
 * @name Command execution inventory
 * @description CWE-agnostic inventory of system command execution calls, surfaced
 *              regardless of data flow (point detection). No vulnerability class is
 *              assumed: the agent decides in Validation whether untrusted input
 *              reaches this call.
 * @kind problem
 * @problem.severity recommendation
 * @security-severity 1.0
 * @id py/command-exec-inventory
 * @tags security
 */

import python
import semmle.python.Concepts

from SystemCommandExecution call
select call, "command-exec"
