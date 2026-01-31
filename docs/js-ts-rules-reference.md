# JavaScript/TypeScript Rules Reference for Native Implementation

This document catalogs rules to implement natively in RMA using tree-sitter.
Prioritized by security impact and detection value.

---

## PRIORITY 1: Security Sinks (MUST IMPLEMENT)

These are high-confidence security vulnerabilities. Implement first.

### Code Injection / XSS
| Rule | Pattern to Detect | Severity | Detection Strategy |
|------|-------------------|----------|-------------------|
| `no-eval` | eval() calls | Critical | Call expression with callee "eval" |
| `no-implied-eval` | Timer functions with string args | Critical | Call with string literal arg |
| `no-new-func` | Function constructor | Critical | New expression with "Function" |
| `jsx-no-script-url` | javascript: protocol in href | Critical | JSX attribute with javascript: |
| `no-danger` | dangerouslySetInnerHTML | Error | JSX attribute name match |
| `no-inner-html` | innerHTML assignment | Error | Assignment to innerHTML property |

### Shell Command Execution  
| Rule | Pattern | Severity | Detection Strategy |
|------|---------|----------|-------------------|
| `no-shell-exec` | subprocess with dynamic args | Critical | Shell calls with string concat |
| `no-dynamic-require` | require(variable) | Warning | Non-literal require arg |

### SQL/NoSQL Injection
| Rule | Pattern | Severity | Detection Strategy |
|------|---------|----------|-------------------|
| `no-sql-injection` | Query with template strings | Critical | String concat in db calls |

### Secrets/Credentials
| Rule | Pattern | Severity | Detection Strategy |
|------|---------|----------|-------------------|
| `no-hardcoded-credentials` | password/apiKey assignments | Error | Assignment with secret names |

---

## PRIORITY 2: Correctness (High-Value Bugs)

### Promise/Async Issues
| Rule | Pattern | Severity | Detection |
|------|---------|----------|-----------|
| `no-floating-promises` | Unhandled promise | Error | Promise without await/catch |
| `no-misused-promises` | Promise in boolean context | Error | if(asyncFn()) |
| `await-thenable` | await on non-Promise | Warning | Await non-Promise |
| `require-await` | async without await | Info | Async body lacks await |
| `no-await-in-loop` | await inside loop | Warning | Await in loop body |

### Type Coercion Bugs
| Rule | Pattern | Severity | Detection |
|------|---------|----------|-----------|
| `eqeqeq` | == instead of === | Warning | Binary with ==/!= |
| `valid-typeof` | typeof typo | Error | Invalid typeof string |

### Control Flow Bugs
| Rule | Pattern | Severity | Detection |
|------|---------|----------|-----------|
| `no-fallthrough` | Missing break | Error | Case without terminator |
| `no-unreachable` | Dead code | Warning | After return/throw |
| `for-direction` | Infinite loop | Error | Wrong loop direction |
| `no-constant-condition` | if(true) | Warning | Literal condition |
| `no-cond-assign` | Assignment in if | Error | = in condition |

### Variable Issues
| Rule | Pattern | Severity | Detection |
|------|---------|----------|-----------|
| `no-unused-vars` | Unused declaration | Warning | No references |
| `no-undef` | Undefined variable | Error | No declaration |
| `no-redeclare` | Duplicate declaration | Error | Same name twice |
| `no-shadow` | Shadowed variable | Warning | Nested same name |

### Array/Object Issues
| Rule | Pattern | Severity | Detection |
|------|---------|----------|-----------|
| `no-sparse-arrays` | Array holes | Warning | [1,,3] |
| `no-dupe-keys` | Duplicate keys | Error | Same key twice |
| `no-duplicate-case` | Duplicate case | Error | Same case value |
| `array-callback-return` | Missing return | Error | map() no return |

---

## PRIORITY 3: Suspicious Patterns (Review Hints)

### React-Specific
| Rule | Pattern | Severity |
|------|---------|----------|
| `no-array-index-key` | key={index} | Warning |
| `no-children-prop` | children as prop | Warning |

### Code Quality  
| Rule | Pattern | Severity |
|------|---------|----------|
| `no-console` | console.* calls | Info |
| `no-debugger` | debugger statement | Warning |
| `no-alert` | alert/confirm/prompt | Warning |
| `no-empty` | Empty blocks | Info |

### Complexity
| Rule | Pattern | Severity |
|------|---------|----------|
| `complexity` | High cyclomatic | Warning |
| `max-depth` | Deep nesting | Warning |
| `max-params` | Too many params | Warning |

---

## Tree-Sitter Node Types

Key node types for rule implementation:

```
call_expression, new_expression, member_expression
assignment_expression, binary_expression, unary_expression
await_expression, template_string
if_statement, for_statement, while_statement
switch_statement, switch_case, return_statement
variable_declaration, function_declaration, arrow_function
jsx_element, jsx_attribute, jsx_expression
identifier, property_identifier
```

---

## Already Implemented in RMA

- ✅ DynamicCodeExecutionRule - eval detection
- ✅ TimerStringRule - setTimeout/setInterval strings  
- ✅ InnerHtmlRule - innerHTML XSS
- ✅ InnerHtmlReadRule - innerHTML read
- ✅ ConsoleLogRule - console.log detection

---

## Implementation Estimate

~8-10 days to achieve 80% coverage of high-value rules natively.
