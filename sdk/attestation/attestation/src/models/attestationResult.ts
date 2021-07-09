// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { AttestationSigner } from ".";
import { GeneratedAttestationResult } from "../generated";
import { _attestationSignerFromGenerated } from "./attestationSigner";

/**
 * Defines the contents of the {@link AttestationResult.sgxCollateral} claim in
 * an {@link AttestationResult}.
 */
export interface AttestationSgxCollateralInfo {
  /**
   * Hex encoded Sha256 hash of the Quoting Enclave Certificates.
   * 
   * See the {@link https://software.intel.com/content/www/us/en/develop/articles/quote-verification-attestation-with-intel-sgx-dcap.html | Intel SGX documentation }
   *  for more information on quote validation.
   */
  qeidcertshash?: string;
  /**
   * Hex encoded Sha256 hash of the Quoting Enclave Certificate CRL.
   * 
   * See the {@link https://software.intel.com/content/www/us/en/develop/articles/quote-verification-attestation-with-intel-sgx-dcap.html | Intel SGX documentation }
   *  for more information on quote validation.
   */
  qeidcrlhash?: string;
  /**
   * Hex encoded Sha256 hash of the Quoting Enclave Identity.
   * 
   * See the {@link https://software.intel.com/content/www/us/en/develop/articles/quote-verification-attestation-with-intel-sgx-dcap.html | Intel SGX documentation }
   *  for more information on quote validation.
   */
  qeidhash?: string;
  /**
   * Hex encoded Sha256 hash of the SGX Quote or OpenEnclave Report validated 
   * by this token.
   * 
   * See the {@link https://software.intel.com/content/www/us/en/develop/articles/quote-verification-attestation-with-intel-sgx-dcap.html | Intel SGX documentation }
   *  for more information on quote validation.
   */
  quotehash?: string;
  /**
   * Hex encoded Sha256 hash of the TCB Info Certificates.
   * 
   * See the {@link https://software.intel.com/content/www/us/en/develop/articles/quote-verification-attestation-with-intel-sgx-dcap.html | Intel SGX documentation }
   *  for more information on quote validation.
   */
  tcbinfocertshash?: string;
  /**
   * Hex encoded Sha256 hash of the TCB Info Certificate CRL.
   * 
   * See the {@link https://software.intel.com/content/www/us/en/develop/articles/quote-verification-attestation-with-intel-sgx-dcap.html | Intel SGX documentation }
   *  for more information on quote validation.
   */
  tcbinfocrlhash?: string;
  /**
   * Hex encoded Sha256 hash of the TCB Info for the device being attested.
   * 
   * See the {@link https://software.intel.com/content/www/us/en/develop/articles/quote-verification-attestation-with-intel-sgx-dcap.html | Intel SGX documentation }
   *  for more information on quote validation.
   */
  tcbinfohash?: string;
}

/**
 * A Microsoft Azure Attestation response token body - the body of a response token issued by MAA
 */
export interface AttestationResult {
  /**
   * Unique Identifier for the token.
   *
   * Corresponds to the 'jti' claim defined in
   * {@link https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7 | RFC 7519 section 4.1.7}
   */
  uniqueId: string;

  /**
   * Returns the issuer of the attestation token. MUST be the same as the
   * endpoint used when constructing the attestation client instance.
   */
  issuer: string;

  /**
   * Returns the "nonce" value if one was specified in the Attest request.
   */
  nonce?: string;

  /**
   * The Schema version of this structure. Current Value: 1.0
   */
  version: string;

  /**
   *  Returns the runtime claims in the token.
   *
   * This value will match the input `runTimeJson` property to the
   * {@link AttestationClient.attestSgxEnclave} or
   * {@link AttestationClient.attestOpenEnclave} API.
   *
   * @remarks
   *
   * The `runtimeClaims` property will only be populated if the
   * `runtimeJson` parameter to the `Attest` API is specified. It will
   * not be populated if the `runtimeData` parameter is specified.
   */
  runtimeClaims: any;
  /**
   * Returns the initialization time claims in the token.
   * This value will match the input `initTimeJson` property to the
   * {@link AttestationClient.attestSgxEnclave} or
   * {@link AttestationClient.attestOpenEnclave} API.
   *
   * @remarks
   *
   *  The `initTimeClaims` property will only be populated if the `initTimeJson`
   *  parameter to the `Attest` API is specified. It will not be populated if
   *  the `initTimeData` parameter is specified.
   */
  inittimeClaims: any;

  /**
   * Returns the set of claims generated by the attestation policy on the instance.
   */
  policyClaims: any;

  /**
   * Returns the verifier which generated this attestation token. Normally one of:
   * "SGX" or "TPM", but others can be specified.
   */
  verifierType: string;
  /**
   * The certificate used to sign the policy object, if specified.
   */
  policySigner?: AttestationSigner;
  /**
   * The base64url encoded SHA256 hash of the BASE64URL encoded policy text
   * used for attestation.
   */
  policyHash: Uint8Array;
  /**
   * True if the enclave is debuggable, false otherwise. Only valid if `verifierType` is SGX.
   */
  isDebuggable?: boolean;

  /**
   * The SGX Product ID for the enclave. Only valid if the `verifierType` field is "SGX"
   */
  productId?: number;
  /**
   * The HEX encoded SGX MRENCLAVE value for the enclave. Only valid if the
   * `verifierType` field is "SGX"
   */
  mrEnclave?: string;

  /**
   * The HEX encoded SGX MRSIGNER value for the enclave. Only valid if the
   * `verifierType` field is "SGX"
   */
  mrSigner?: string;

  /**
   * The SGX SVN value for the enclave. Only valid if the `verifierType` field is "SGX"
   */
  svn?: number;

  /**
   * Returns the value of the runtime_data field specified as an input to the
   * {@link AttestationClient.attestSgxEnclave} or {@link AttestationClient.attestOpenEnclave} API.
   *
   * @remarks
   *
   * The `enclaveHeldData` property will only be populated if the
   * `runtimeData` parameter to the `Attest` API is specified.
   */
  enclaveHeldData?: Uint8Array;

  /**
   * Returns a set of information describing the complete set of inputs to the
   * Attestation validation logic.
   * 
   * See the {@link https://software.intel.com/content/www/us/en/develop/articles/quote-verification-attestation-with-intel-sgx-dcap.html | Intel SGX documentation }
   *  for more information on quote validation.
   */
  sgxCollateral?: AttestationSgxCollateralInfo;
}

/**
 * A Microsoft Azure Attestation response token body - the body of a response token issued by MAA
 */
export class AttestationResultImpl implements AttestationResult {
  /**
   *
   * @param params - The parameters for the constructor.
   *
   * @hidden
   */
  constructor(params: {
    issuer: string;
    version: string;
    nonce?: string;
    uniqueId: string;
    runtimeClaims?: any;
    inittimeClaims?: any;
    policyClaims?: any;
    verifierType: string;
    policySigner?: AttestationSigner;
    policyHash: Uint8Array;
    isDebuggable?: boolean;
    productId?: number;
    mrEnclave?: string;
    mrSigner?: string;
    svn?: number;
    enclaveHeldData?: Uint8Array;
    sgxCollateral?: any;
  }) {
    this._issuer = params.issuer;
    this._nonce = params.nonce;
    this._version = params.version;
    this._uniqueId = params.uniqueId;
    this._runtimeClaims = params.runtimeClaims;
    this._inittimeClaims = params.inittimeClaims;
    this._policyClaims = params.policyClaims;
    this._verifierType = params.verifierType;
    this._policySigner = params.policySigner;
    this._policyHash = params.policyHash;
    this._isDebuggable = params.isDebuggable;
    this._productId = params.productId;
    this._mrEnclave = params.mrEnclave;
    this._mrSigner = params.mrSigner;
    this._svn = params.svn;
    this._enclaveHeldData = params.enclaveHeldData;
    this._sgxCollateral = params.sgxCollateral;
  }

  private _issuer: string;
  private _version: string;
  private _nonce?: string;
  private _uniqueId: string;
  private _runtimeClaims?: any;
  private _inittimeClaims?: any;
  private _policyClaims?: any;
  private _verifierType: string;
  private _policySigner?: AttestationSigner;
  private _policyHash: Uint8Array;
  private _isDebuggable?: boolean;
  private _productId?: number;
  private _mrEnclave?: string;
  private _mrSigner?: string;
  private _svn?: number;
  private _enclaveHeldData?: Uint8Array;
  private _sgxCollateral?: any;

  /**
   * Unique Identifier for the token
   *
   */
  get uniqueId(): string {
    return this._uniqueId;
  }

  /**
   * Returns the issuer of the attestation token. MUST be the same as the
   * endpoint used when constructing the attestation client instance.
   */
  get issuer(): string {
    return this._issuer;
  }

  /**
   * Returns the "nonce" value specified in the Attest request.
   */
  get nonce(): string | undefined {
    return this._nonce;
  }

  /**
   * The Schema version of this structure. Current Value: 1.0
   */
  get version(): string {
    return this._version;
  }

  /**
   * Runtime Claims
   */
  get runtimeClaims(): any {
    return this._runtimeClaims;
  }
  /**
   * Inittime Claims
   */
  get inittimeClaims(): any {
    return this._inittimeClaims;
  }

  /**
   * Policy Generated Claims
   */
  get policyClaims(): any {
    return this._policyClaims;
  }
  /**
   * The Attestation type being attested.
   */
  get verifierType(): string {
    return this._verifierType;
  }
  /**
   * The certificate used to sign the policy object, if specified.
   */
  get policySigner(): AttestationSigner | undefined {
    return this._policySigner;
  }
  /**
   * The SHA256 hash of the BASE64URL encoded policy text used for attestation
   */
  get policyHash(): Uint8Array {
    return this._policyHash;
  }
  /**
   * True if the enclave is debuggable, false otherwise
   */
  get isDebuggable(): boolean | undefined {
    return this._isDebuggable;
  }
  /**
   * The SGX Product ID for the enclave.
   */
  get productId(): number | undefined {
    return this._productId;
  }
  /**
   * The HEX encoded SGX MRENCLAVE value for the enclave.
   */
  get mrEnclave(): string | undefined {
    return this._mrEnclave;
  }
  /**
   * The HEX encoded SGX MRSIGNER value for the enclave.
   */
  get mrSigner(): string | undefined {
    return this._mrSigner;
  }
  /**
   * The SGX SVN value for the enclave.
   */
  get svn(): number | undefined {
    return this._svn;
  }
  /**
   * A copy of the RuntimeData specified as an input to the attest call.
   */
  get enclaveHeldData(): Uint8Array | undefined {
    return this._enclaveHeldData;
  }
  /**
   * The SGX SVN value for the enclave.
   */
  get sgxCollateral(): any {
    return this._sgxCollateral;
  }
}

/**
 *
 * @param generated - Generated attestation result object.
 * @returns newly created AttestationResult from the generated result.
 *
 * @internal
 */
export function _attestationResultFromGenerated(
  generated: GeneratedAttestationResult
): AttestationResultImpl {
  return new AttestationResultImpl({
    issuer: generated.iss,
    version: generated.version,
    nonce: generated.nonce,
    uniqueId: generated.jti,
    policySigner: generated.policySigner
      ? _attestationSignerFromGenerated(generated.policySigner)
      : undefined,
    runtimeClaims: generated.runtimeClaims,
    inittimeClaims: generated.inittimeClaims,
    policyClaims: generated.policyClaims,
    verifierType: generated.verifierType,
    policyHash: generated.policyHash,
    isDebuggable: generated.isDebuggable,
    productId: generated.productId,
    mrEnclave: generated.mrEnclave,
    mrSigner: generated.mrSigner,
    svn: generated.svn,
    enclaveHeldData: generated.enclaveHeldData,
    sgxCollateral: generated.sgxCollateral
  });
}
