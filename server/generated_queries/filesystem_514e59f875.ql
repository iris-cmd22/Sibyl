/**
 * @name Filesystem access inventory
 * @description CWE-agnostic inventory of filesystem access calls, surfaced regardless
 *              of data flow. No vulnerability class is assumed: the agent decides in
 *              Validation whether untrusted input reaches this call.
 * @kind problem
 * @problem.severity recommendation
 * @security-severity 1.0
 * @id py/filesystem-access-inventory
 * @tags security
 */

import python
import semmle.python.Concepts

from FileSystemAccess call
select call, "filesystem"
