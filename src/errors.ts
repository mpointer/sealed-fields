/** Base class for every error this library throws deliberately. */
export class SealedFieldsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SealedFieldsError";
  }
}

/** A seal/unseal/blindIndex op was attempted with no key configured (strict mode). */
export class KeyNotConfiguredError extends SealedFieldsError {
  constructor(message: string) {
    super(message);
    this.name = "KeyNotConfiguredError";
  }
}

/** A token names a key version that is not in the namespace's keyring. */
export class UnknownKeyVersionError extends SealedFieldsError {
  readonly version: string;
  constructor(version: string, namespace: string) {
    super(
      `unseal: token names key version "${version}" which is not in the "${namespace}" keyring. ` +
        `Add it to retired keys, or set onUnknownVersion: "passthrough" during an active migration.`,
    );
    this.name = "UnknownKeyVersionError";
    this.version = version;
  }
}

/**
 * More than half of attempted unseals across a batch failed. That pattern is a
 * wrong or missing key, not isolated row corruption, and must not be served
 * silently as a page of nulls.
 */
export class SystemicUnsealError extends SealedFieldsError {
  readonly failures: number;
  readonly attempts: number;
  constructor(failures: number, attempts: number) {
    super(
      `systemic unseal failure: ${failures}/${attempts} attempted unseals failed. ` +
        `This usually means the wrong key is configured for this namespace.`,
    );
    this.name = "SystemicUnsealError";
    this.failures = failures;
    this.attempts = attempts;
  }
}
