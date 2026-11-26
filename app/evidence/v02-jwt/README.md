# V-02 - JWT / Broken Authentication

## Vulnerability

CWE-345: Insufficient Verification of Data Authenticity.

## Objective

Demonstrate the risks of accepting JWT claims without verifying
the authenticity and integrity of the token.

## Vulnerable behavior

The laboratory function `unsafeDecodeToken()` uses `jwt.decode()`,
which extracts the token payload without validating its signature.

## Security correction

The production authentication middleware uses `jwt.verify()` with:

- Explicit HS256 algorithm.
- Configured JWT secret.
- Issuer validation.
- Audience validation.
- Token expiration validation.
- Validation of required claims.

## Validation

Eight Jest tests were executed successfully.

See `test-results.txt` for the execution results.

## Security restriction

The vulnerable laboratory implementation is not imported into
the production application and must not be exposed through an API.
