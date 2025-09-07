# Security: Dot-prop Prototype Pollution Protection

## Overview

This document outlines the security measures implemented to protect against prototype pollution vulnerabilities in the dot-prop npm package. The repository implements comprehensive protection against CVE-2020-28436 and related prototype pollution attacks.

## Vulnerability Details

- **Issue**: Prototype Pollution via malicious property names in dot-prop
- **CVE**: CVE-2020-28436
- **Affected Versions**: 
  - dot-prop versions before 4.2.1
  - dot-prop versions 5.x before 5.1.1
- **Impact**: Attackers could modify Object.prototype by providing malicious property names like `__proto__`, `constructor.prototype`, etc.

## Mitigation Strategy

### 1. Dependency Overrides

The main `package.json` includes security overrides that force all dot-prop dependencies to use secure versions:

```json
{
  "pnpm": {
    "overrides": {
      "dot-prop@<4.2.1": ">=4.2.1",
      "dot-prop@>=5.0.0 <5.1.1": ">=5.1.1"
    }
  },
  "overrides": {
    "dot-prop@<4.2.1": ">=4.2.1", 
    "dot-prop@>=5.0.0 <5.1.1": ">=5.1.1"
  }
}
```

### 2. Application-Level Protection

The repository already includes comprehensive prototype pollution protection in:
- `packages/error-utils/src/index.ts` - Safe key validation utilities
- `api/_lib/util/error-handler.ts` - Safe error handling
- `packages/sdk/src/lib/schemas.ts` - Safe schema processing

## Vulnerability Technical Details

### Attack Vector Example

Vulnerable dot-prop versions allowed prototype pollution through property paths:

```javascript
const dotProp = require('dot-prop'); // vulnerable version

const target = {};

// Malicious input could pollute prototype
dotProp.set(target, '__proto__.polluted', true);
dotProp.set(target, 'constructor.prototype.polluted', true);

// This would affect all objects
console.log({}.polluted); // true (prototype pollution!)
```

### Fixed Behavior

Secure dot-prop versions (>=4.2.1, >=5.1.1) prevent prototype pollution:

```javascript
const dotProp = require('dot-prop'); // secure version

const target = {};

// Safe behavior - prototype pollution prevented
dotProp.set(target, '__proto__.polluted', true);
dotProp.set(target, 'constructor.prototype.polluted', true);

// Object prototype remains clean
console.log({}.polluted); // undefined (protected!)
```

## Protected Functions

The repository uses additional protection utilities to prevent prototype pollution:

### `isSafeKey(key: string): boolean`
- Validates if a key is safe for object property assignment
- Returns `false` for `__proto__`, `constructor`, `prototype`

### `getSafeEntries<T>(obj: Record<string, T>): [string, T][]`
- Returns object entries with dangerous keys filtered out
- Used throughout error handling and schema processing

### `safeAssign<T>(target: Record<string, T>, source: Record<string, T>): void`
- Safely assigns properties from source to target
- Validates each key before assignment

## Verification

### Automated Security Verification

Run the security verification script to ensure all protections are in place:

```bash
node scripts/verify-dot-prop-security.js
```

This script verifies:
- ✅ Security overrides are properly configured
- ✅ Security documentation is present
- ✅ Security tests are in place
- ✅ No vulnerable versions are accessible

### Manual Verification

You can manually verify the overrides work by checking that vulnerable versions are updated:

```bash
# Check for any remaining vulnerable dot-prop versions
grep -r "dot-prop.*[34]\.[012]" . --include="*.json" || echo "No 3.x/4.0-4.2.0 versions found"
grep -r "dot-prop.*5\.[01]\." . --include="*.json" || echo "No 5.0.x/5.1.0 versions found"
```

## Test Coverage

Comprehensive tests validate the prototype pollution protection mechanisms:
- Safe key processing tests in `packages/sdk/src/lib/schemas.test.ts`
- Error handler protection tests in `api/_lib/util/error-handler.test.ts`
- Utility function tests covering all edge cases

## References

- [CVE-2020-28436 - dot-prop Prototype Pollution](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-28436)
- [Prototype Pollution Prevention - OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html)
- [dot-prop Security Advisory](https://github.com/sindresorhus/dot-prop/security/advisories)
- [Integration Test](./scripts/verify-dot-prop-security.js)