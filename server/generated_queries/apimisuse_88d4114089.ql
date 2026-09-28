/**
 * @name Templated weak/insecure API usage
 * @description Agent-supplied name-based detection of calls to weak or insecure
 *              APIs (e.g. weak hashes, broken ciphers, insecure randomness).
 *              Call names and/or bad constant arguments are injected by the
 *              run_api_misuse_query tool. Point detection, not data flow.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.0
 * @id py/templated-api-misuse-cwe-328
 * @tags security
 *       external/cwe/cwe-328
 */

import python
import semmle.python.dataflow.new.DataFlow

/** A call whose attribute name (obj.NAME(...)) or bare name (NAME(...)) is in `names`. */
bindingset[names]
private predicate callNameIn(DataFlow::CallCfgNode call, string names) {
  call.getFunction().(DataFlow::AttrRead).getAttributeName() = names
  or
  call.getFunction().asExpr().(Name).getId() = names
}

/** A call that passes a string-literal argument equal (case-insensitive) to `bad`. */
bindingset[bad]
private predicate callHasBadConst(DataFlow::CallCfgNode call, string bad) {
  exists(StringLiteral s |
    s = call.getArg(_).asExpr() and
    s.getText().toLowerCase() = bad
  )
}

from DataFlow::CallCfgNode call, string reason
where
  (
    callNameIn(call, ["md5", "sha1"]) and reason = "call to a weak/insecure API"
  )
  or
  (
    callHasBadConst(call, ["md5", "sha1"]) and reason = "weak algorithm/parameter passed as argument"
  )
select call, "Insecure cryptographic API usage: " + reason + " (" + call.toString() + ")."
