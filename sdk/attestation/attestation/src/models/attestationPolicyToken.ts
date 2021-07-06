// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { StoredAttestationPolicy } from "./storedAttestationPolicy";
import { AttestationSigningKey } from "./attestationSigningKey";
import { AttestationToken } from "./attestationToken";

/**
 *
 * An AttestationToken represents an RFC 7515 JSON Web Signature object.
 *
 * It can represent either the token returned by the attestation service,
 * or it can be used to create a token locally which can be used to verify
 * attestation policy changes.
 */
export class AttestationPolicyToken extends AttestationToken {
  /** Constructs an AttestationToken containing an Attestation Policy document.
   *
   * @param policy - Attestation policy to embed in the attestation token.
   * @param signer - optional signing key used to sign the attestation token.
   *
   * @remarks Note that if the attestation instance is running in `Isolated` mode,
   *      the signer is required. If the attestation instance is running in `AAD` mode,
   *      it is optional.
   */
  public constructor(policy: string, signer?: AttestationSigningKey) {
    const token = AttestationToken.create({
      body: new StoredAttestationPolicy(policy).serialize(),
      signer: signer
    });
    super(token.serialize());
  }
}
