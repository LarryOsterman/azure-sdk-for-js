// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

export * from "./attestationSigner";
export * from "./attestationSigningKey";
export * from "./attestationToken";
export * from "./attestationData";
export * from "./attestationResponse";
export * from "./storedAttestationPolicy";
export * from "./policyResult";

/**
 * An error response from Attestation.
 */
export interface CloudError {
  /**
   * An error response from Attestation.
   */
  error?: CloudErrorBody;
}

/**
 * An error response from Attestation.
 */
export interface CloudErrorBody {
  /**
   * An identifier for the error. Codes are invariant and are intended to be consumed programmatically.
   */
  code?: string;
  /**
   * A message describing the error, intended to be suitable for displaying in a user interface.
   */
  message?: string;
}

/**
 * The response to an attestation policy management API
 */
export interface PolicyCertificatesModifyResponse {
  /**
   * An RFC7519 JSON Web Token structure whose body is a PolicyCertificatesModificationResult object.
   */
  token?: string;
}

export interface JsonWebKeySet {
  /**
   * The value of the "keys" parameter is an array of JWK values.  By
   * default, the order of the JWK values within the array does not imply
   * an order of preference among them, although applications of JWK Sets
   * can choose to assign a meaning to the order for their purposes, if
   * desired.
   */
  keys?: JsonWebKey[];
}

export interface JsonWebKey {
  /**
   * The "alg" (algorithm) parameter identifies the algorithm intended for
   * use with the key.  The values used should either be registered in the
   * IANA "JSON Web Signature and Encryption Algorithms" registry
   * established by [JWA] or be a value that contains a Collision-
   * Resistant Name.
   */
  alg?: string;
  /**
   * The "crv" (curve) parameter identifies the curve type
   */
  crv?: string;
  /**
   * RSA private exponent or ECC private key
   */
  d?: string;
  /**
   * RSA Private Key Parameter
   */
  dp?: string;
  /**
   * RSA Private Key Parameter
   */
  dq?: string;
  /**
   * RSA public exponent, in Base64
   */
  e?: string;
  /**
   * Symmetric key
   */
  k?: string;
  /**
   * The "kid" (key ID) parameter is used to match a specific key.  This
   * is used, for instance, to choose among a set of keys within a JWK Set
   * during key rollover.  The structure of the "kid" value is
   * unspecified.  When "kid" values are used within a JWK Set, different
   * keys within the JWK Set SHOULD use distinct "kid" values.  (One
   * example in which different keys might use the same "kid" value is if
   * they have different "kty" (key type) values but are considered to be
   * equivalent alternatives by the application using them.)  The "kid"
   * value is a case-sensitive string.
   */
  kid?: string;
  /**
   * The "kty" (key type) parameter identifies the cryptographic algorithm
   * family used with the key, such as "RSA" or "EC". "kty" values should
   * either be registered in the IANA "JSON Web Key Types" registry
   * established by [JWA] or be a value that contains a Collision-
   * Resistant Name.  The "kty" value is a case-sensitive string.
   */
  kty: string;
  /**
   * RSA modulus, in Base64
   */
  n?: string;
  /**
   * RSA secret prime
   */
  p?: string;
  /**
   * RSA secret prime, with p \< q
   */
  q?: string;
  /**
   * RSA Private Key Parameter
   */
  qi?: string;
  /**
   * Use ("public key use") identifies the intended use of
   * the public key. The "use" parameter is employed to indicate whether
   * a public key is used for encrypting data or verifying the signature
   * on data. Values are commonly "sig" (signature) or "enc" (encryption).
   */
  use?: string;
  /**
   * X coordinate for the Elliptic Curve point
   */
  x?: string;
  /**
   * The "x5c" (X.509 certificate chain) parameter contains a chain of one
   * or more PKIX certificates [RFC5280].  The certificate chain is
   * represented as a JSON array of certificate value strings.  Each
   * string in the array is a base64-encoded (Section 4 of [RFC4648] --
   * not base64url-encoded) DER [ITU.X690.1994] PKIX certificate value.
   * The PKIX certificate containing the key value MUST be the first
   * certificate.
   */
  x5C?: string[];
  /**
   * Y coordinate for the Elliptic Curve point
   */
  y?: string;
}

/**
 * The result of a policy certificate modification
 */
export interface PolicyCertificatesModificationResult {
  /**
   * Hex encoded SHA1 Hash of the binary representation certificate which was added or removed
   */
  certificateThumbprint?: string;
  /**
   * The result of the operation
   */
  certificateResolution?: CertificateModification;
}

/**
 * A Microsoft Azure Attestation response token body - the body of a response token issued by MAA
 */
export interface AttestationResult {
  /**
   * Unique Identifier for the token
   */
  jti?: string;
  /**
   * The Principal who issued the token
   */
  iss?: string;
  /**
   * The time at which the token was issued, in the number of seconds since 1970-01-0T00:00:00Z UTC
   */
  iat?: number;
  /**
   * The expiration time after which the token is no longer valid, in the number of seconds since 1970-01-0T00:00:00Z UTC
   */
  exp?: number;
  /**
   * The not before time before which the token cannot be considered valid, in the number of seconds since 1970-01-0T00:00:00Z UTC
   */
  nbf?: number;
  /**
   * An RFC 7800 Proof of Possession Key
   */
  cnf?: any;
  /**
   * The Nonce input to the attestation request, if provided.
   */
  nonce?: string;
  /**
   * The Schema version of this structure. Current Value: 1.0
   */
  version?: string;
  /**
   * Runtime Claims
   */
  runtimeClaims?: any;
  /**
   * Inittime Claims
   */
  inittimeClaims?: any;
  /**
   * Policy Generated Claims
   */
  policyClaims?: any;
  /**
   * The Attestation type being attested.
   */
  verifierType?: string;
  /**
   * The certificate used to sign the policy object, if specified.
   */
  policySigner?: JsonWebKey;
  /**
   * The SHA256 hash of the BASE64URL encoded policy text used for attestation
   */
  policyHash?: Uint8Array;
  /**
   * True if the enclave is debuggable, false otherwise
   */
  isDebuggable?: boolean;
  /**
   * The SGX Product ID for the enclave.
   */
  productId?: number;
  /**
   * The HEX encoded SGX MRENCLAVE value for the enclave.
   */
  mrEnclave?: string;
  /**
   * The HEX encoded SGX MRSIGNER value for the enclave.
   */
  mrSigner?: string;
  /**
   * The SGX SVN value for the enclave.
   */
  svn?: number;
  /**
   * A copy of the RuntimeData specified as an input to the attest call.
   */
  enclaveHeldData?: Uint8Array;
  /**
   * The SGX SVN value for the enclave.
   */
  sgxCollateral?: any;
  /**
   * DEPRECATED: Private Preview version of x-ms-ver claim.
   */
  deprecatedVersion?: string;
  /**
   * DEPRECATED: Private Preview version of x-ms-sgx-is-debuggable claim.
   */
  deprecatedIsDebuggable?: boolean;
  /**
   * DEPRECATED: Private Preview version of x-ms-sgx-collateral claim.
   */
  deprecatedSgxCollateral?: any;
  /**
   * DEPRECATED: Private Preview version of x-ms-sgx-ehd claim.
   */
  deprecatedEnclaveHeldData?: Uint8Array;
  /**
   * DEPRECATED: Private Preview version of x-ms-sgx-ehd claim.
   */
  deprecatedEnclaveHeldData2?: Uint8Array;
  /**
   * DEPRECATED: Private Preview version of x-ms-sgx-product-id
   */
  deprecatedProductId?: number;
  /**
   * DEPRECATED: Private Preview version of x-ms-sgx-mrenclave.
   */
  deprecatedMrEnclave?: string;
  /**
   * DEPRECATED: Private Preview version of x-ms-sgx-mrsigner.
   */
  deprecatedMrSigner?: string;
  /**
   * DEPRECATED: Private Preview version of x-ms-sgx-svn.
   */
  deprecatedSvn?: number;
  /**
   * DEPRECATED: Private Preview version of x-ms-tee.
   */
  deprecatedTee?: string;
  /**
   * DEPRECATED: Private Preview version of x-ms-policy-signer
   */
  deprecatedPolicySigner?: JsonWebKey;
  /**
   * DEPRECATED: Private Preview version of x-ms-policy-hash
   */
  deprecatedPolicyHash?: Uint8Array;
  /**
   * DEPRECATED: Private Preview version of nonce
   */
  deprecatedRpData?: string;
}

/**
 * Known values of {@link AttestationType} that the service accepts.
 */
export enum KnownAttestationType {
  /**
   * Intel Software Guard eXtensions
   */
  SgxEnclave = "SgxEnclave",
  /**
   * OpenEnclave extensions to SGX
   */
  OpenEnclave = "OpenEnclave",
  /**
   * Edge TPM Virtualization Based Security
   */
  Tpm = "Tpm"
}

/**
 * Defines values for AttestationType.
 * {@link KnownAttestationType} can be used interchangeably with AttestationType,
 *  this enum contains the known values that the service supports.
 * ### Know values supported by the service
 * **SgxEnclave**: Intel Software Guard eXtensions
 * **OpenEnclave**: OpenEnclave extensions to SGX
 * **Tpm**: Edge TPM Virtualization Based Security
 */
export type AttestationType = string;

/**
 * Known values of {@link DataType} that the service accepts.
 */
export enum KnownDataType {
  /**
   * The contents of the field should be treated as binary and not interpreted by MAA.
   */
  Binary = "Binary",
  /**
   * The contents of the field should be treated as a JSON object and may be further interpreted by MAA.
   */
  Json = "JSON"
}

/**
 * Defines values for DataType.
 * {@link KnownDataType} can be used interchangeably with DataType,
 *  this enum contains the known values that the service supports.
 * ### Know values supported by the service
 * **Binary**: The contents of the field should be treated as binary and not interpreted by MAA.
 * **JSON**: The contents of the field should be treated as a JSON object and may be further interpreted by MAA.
 */
export type DataType = string;

/**
 * Known values of {@link CertificateModification} that the service accepts.
 */
export enum KnownCertificateModification {
  /**
   * After the operation was performed, the certificate is in the set of certificates.
   */
  IsPresent = "IsPresent",
  /**
   * After the operation was performed, the certificate is no longer present in the set of certificates.
   */
  IsAbsent = "IsAbsent"
}

/**
 * Defines values for CertificateModification.
 * {@link KnownCertificateModification} can be used interchangeably with CertificateModification,
 *  this enum contains the known values that the service supports.
 * ### Know values supported by the service
 * **IsPresent**: After the operation was performed, the certificate is in the set of certificates.
 * **IsAbsent**: After the operation was performed, the certificate is no longer present in the set of certificates.
 */
export type CertificateModification = string;

/**
 * Known values of {@link PolicyModification} that the service accepts.
 */
export enum KnownPolicyModification {
  /**
   * The specified policy object was updated.
   */
  Updated = "Updated",
  /**
   * The specified policy object was removed.
   */
  Removed = "Removed"
}

/**
 * Defines values for PolicyModification.
 * {@link KnownPolicyModification} can be used interchangeably with PolicyModification,
 *  this enum contains the known values that the service supports.
 * ### Know values supported by the service
 * **Updated**: The specified policy object was updated.
 * **Removed**: The specified policy object was removed.
 */
export type PolicyModification = string;

/**
 * Contains response data for the add operation.
 */
export type PolicyCertificatesAddResponse = PolicyCertificatesModifyResponse;

/**
 * Contains response data for the remove operation.
 */
export type PolicyCertificatesRemoveResponse = PolicyCertificatesModifyResponse;
