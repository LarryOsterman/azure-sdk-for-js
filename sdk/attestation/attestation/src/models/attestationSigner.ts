// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

import { encodeByteArray } from "../../test/utils/base64url";

import { JsonWebKey } from "../generated/models";
import { base64DecodeString } from "../utils/base64";
import { pemFromBase64 } from "../utils/helpers";

/**
 * An AttestationSigner represents a signing certificate chain/Key ID combination
 * returned by the attestation service.
 */
export class AttestationSigner {
  /**
   * @param key - JSON Web Key describing the attestation signer.
   */
  constructor(args: { keyId?: string; certificates: Uint8Array[] }) {
    if (args.keyId) {
      this.keyId = args.keyId.toString();
    }

    this.certificates = [];
    args.certificates.forEach((cert) => {
      const pemCert = pemFromBase64(encodeByteArray(cert), "CERTIFICATE");

      this.certificates.push(pemCert);
    });
  }

  /**
   * The Key ID for the signer, as defined by the "kid" parameter in
   * {@link https://datatracker.ietf.org/doc/html/rfc7517#section-4.5 | RFC 7517 section 4.5}
   */
  keyId?: string;

  /**
   * An array of X.509 DER encoded certificates one of which will be used to
   * sign an attestation token. Also the "x5c" parameter in
   * {@link https://datatracker.ietf.org/doc/html/rfc7517#section-4.7 | RFC 7517 section 4.7}
   */

  certificates: string[];
}

/**
 *
 * @param key  - JsonWebKey for signing key.
 * @returns AttestationSigner created from the JsonWebKey.
 *
 * @internal
 */
export function _attestationSignerFromGenerated(key?: JsonWebKey): AttestationSigner {
  return new AttestationSigner({
    keyId: key?.kid,
    certificates: key?.x5C?.map(base64DecodeString) ?? []
  });
}
