/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License.
 *
 * Code generated by Microsoft (R) AutoRest Code Generator.
 * Changes may cause incorrect behavior and will be lost if the code is regenerated.
 */

import * as coreHttp from "@azure/core-http";
import * as Mappers from "../models/mappers";
import * as Parameters from "../models/parameters";
import { StorageClientContext } from "../storageClientContext";
import {
  ShareCreateOptionalParams,
  ShareCreateResponse,
  ShareGetPropertiesOptionalParams,
  ShareGetPropertiesResponse,
  ShareDeleteOptionalParams,
  ShareDeleteResponse,
  ShareAcquireLeaseOptionalParams,
  ShareAcquireLeaseResponse,
  ShareReleaseLeaseOptionalParams,
  ShareReleaseLeaseResponse,
  ShareChangeLeaseOptionalParams,
  ShareChangeLeaseResponse,
  ShareRenewLeaseOptionalParams,
  ShareRenewLeaseResponse,
  ShareBreakLeaseOptionalParams,
  ShareBreakLeaseResponse,
  ShareCreateSnapshotOptionalParams,
  ShareCreateSnapshotResponse,
  SharePermission,
  ShareCreatePermissionOptionalParams,
  ShareCreatePermissionResponse,
  ShareGetPermissionOptionalParams,
  ShareGetPermissionResponse,
  ShareSetPropertiesOptionalParams,
  ShareSetPropertiesResponse,
  ShareSetMetadataOptionalParams,
  ShareSetMetadataResponse,
  ShareGetAccessPolicyOptionalParams,
  ShareGetAccessPolicyResponse,
  ShareSetAccessPolicyOptionalParams,
  ShareSetAccessPolicyResponse,
  ShareGetStatisticsOptionalParams,
  ShareGetStatisticsResponse,
  ShareRestoreOptionalParams,
  ShareRestoreResponse
} from "../models";

/** Class representing a Share. */
export class Share {
  private readonly client: StorageClientContext;

  /**
   * Initialize a new instance of the class Share class.
   * @param client Reference to the service client
   */
  constructor(client: StorageClientContext) {
    this.client = client;
  }

  /**
   * Creates a new share under the specified account. If the share with the same name already exists, the
   * operation fails.
   * @param options The options parameters.
   */
  create(options?: ShareCreateOptionalParams): Promise<ShareCreateResponse> {
    const operationArguments: coreHttp.OperationArguments = {
      options: coreHttp.operationOptionsToRequestOptionsBase(options || {})
    };
    return this.client.sendOperationRequest(
      operationArguments,
      createOperationSpec
    ) as Promise<ShareCreateResponse>;
  }

  /**
   * Returns all user-defined metadata and system properties for the specified share or share snapshot.
   * The data returned does not include the share's list of files.
   * @param options The options parameters.
   */
  getProperties(
    options?: ShareGetPropertiesOptionalParams
  ): Promise<ShareGetPropertiesResponse> {
    const operationArguments: coreHttp.OperationArguments = {
      options: coreHttp.operationOptionsToRequestOptionsBase(options || {})
    };
    return this.client.sendOperationRequest(
      operationArguments,
      getPropertiesOperationSpec
    ) as Promise<ShareGetPropertiesResponse>;
  }

  /**
   * Operation marks the specified share or share snapshot for deletion. The share or share snapshot and
   * any files contained within it are later deleted during garbage collection.
   * @param options The options parameters.
   */
  delete(options?: ShareDeleteOptionalParams): Promise<ShareDeleteResponse> {
    const operationArguments: coreHttp.OperationArguments = {
      options: coreHttp.operationOptionsToRequestOptionsBase(options || {})
    };
    return this.client.sendOperationRequest(
      operationArguments,
      deleteOperationSpec
    ) as Promise<ShareDeleteResponse>;
  }

  /**
   * The Lease Share operation establishes and manages a lock on a share, or the specified snapshot for
   * set and delete share operations.
   * @param options The options parameters.
   */
  acquireLease(
    options?: ShareAcquireLeaseOptionalParams
  ): Promise<ShareAcquireLeaseResponse> {
    const operationArguments: coreHttp.OperationArguments = {
      options: coreHttp.operationOptionsToRequestOptionsBase(options || {})
    };
    return this.client.sendOperationRequest(
      operationArguments,
      acquireLeaseOperationSpec
    ) as Promise<ShareAcquireLeaseResponse>;
  }

  /**
   * The Lease Share operation establishes and manages a lock on a share, or the specified snapshot for
   * set and delete share operations.
   * @param leaseId Specifies the current lease ID on the resource.
   * @param options The options parameters.
   */
  releaseLease(
    leaseId: string,
    options?: ShareReleaseLeaseOptionalParams
  ): Promise<ShareReleaseLeaseResponse> {
    const operationArguments: coreHttp.OperationArguments = {
      leaseId,
      options: coreHttp.operationOptionsToRequestOptionsBase(options || {})
    };
    return this.client.sendOperationRequest(
      operationArguments,
      releaseLeaseOperationSpec
    ) as Promise<ShareReleaseLeaseResponse>;
  }

  /**
   * The Lease Share operation establishes and manages a lock on a share, or the specified snapshot for
   * set and delete share operations.
   * @param leaseId Specifies the current lease ID on the resource.
   * @param options The options parameters.
   */
  changeLease(
    leaseId: string,
    options?: ShareChangeLeaseOptionalParams
  ): Promise<ShareChangeLeaseResponse> {
    const operationArguments: coreHttp.OperationArguments = {
      leaseId,
      options: coreHttp.operationOptionsToRequestOptionsBase(options || {})
    };
    return this.client.sendOperationRequest(
      operationArguments,
      changeLeaseOperationSpec
    ) as Promise<ShareChangeLeaseResponse>;
  }

  /**
   * The Lease Share operation establishes and manages a lock on a share, or the specified snapshot for
   * set and delete share operations.
   * @param leaseId Specifies the current lease ID on the resource.
   * @param options The options parameters.
   */
  renewLease(
    leaseId: string,
    options?: ShareRenewLeaseOptionalParams
  ): Promise<ShareRenewLeaseResponse> {
    const operationArguments: coreHttp.OperationArguments = {
      leaseId,
      options: coreHttp.operationOptionsToRequestOptionsBase(options || {})
    };
    return this.client.sendOperationRequest(
      operationArguments,
      renewLeaseOperationSpec
    ) as Promise<ShareRenewLeaseResponse>;
  }

  /**
   * The Lease Share operation establishes and manages a lock on a share, or the specified snapshot for
   * set and delete share operations.
   * @param options The options parameters.
   */
  breakLease(
    options?: ShareBreakLeaseOptionalParams
  ): Promise<ShareBreakLeaseResponse> {
    const operationArguments: coreHttp.OperationArguments = {
      options: coreHttp.operationOptionsToRequestOptionsBase(options || {})
    };
    return this.client.sendOperationRequest(
      operationArguments,
      breakLeaseOperationSpec
    ) as Promise<ShareBreakLeaseResponse>;
  }

  /**
   * Creates a read-only snapshot of a share.
   * @param options The options parameters.
   */
  createSnapshot(
    options?: ShareCreateSnapshotOptionalParams
  ): Promise<ShareCreateSnapshotResponse> {
    const operationArguments: coreHttp.OperationArguments = {
      options: coreHttp.operationOptionsToRequestOptionsBase(options || {})
    };
    return this.client.sendOperationRequest(
      operationArguments,
      createSnapshotOperationSpec
    ) as Promise<ShareCreateSnapshotResponse>;
  }

  /**
   * Create a permission (a security descriptor).
   * @param sharePermission A permission (a security descriptor) at the share level.
   * @param options The options parameters.
   */
  createPermission(
    sharePermission: SharePermission,
    options?: ShareCreatePermissionOptionalParams
  ): Promise<ShareCreatePermissionResponse> {
    const operationArguments: coreHttp.OperationArguments = {
      sharePermission,
      options: coreHttp.operationOptionsToRequestOptionsBase(options || {})
    };
    return this.client.sendOperationRequest(
      operationArguments,
      createPermissionOperationSpec
    ) as Promise<ShareCreatePermissionResponse>;
  }

  /**
   * Returns the permission (security descriptor) for a given key
   * @param filePermissionKey Key of the permission to be set for the directory/file.
   * @param options The options parameters.
   */
  getPermission(
    filePermissionKey: string,
    options?: ShareGetPermissionOptionalParams
  ): Promise<ShareGetPermissionResponse> {
    const operationArguments: coreHttp.OperationArguments = {
      filePermissionKey,
      options: coreHttp.operationOptionsToRequestOptionsBase(options || {})
    };
    return this.client.sendOperationRequest(
      operationArguments,
      getPermissionOperationSpec
    ) as Promise<ShareGetPermissionResponse>;
  }

  /**
   * Sets properties for the specified share.
   * @param options The options parameters.
   */
  setProperties(
    options?: ShareSetPropertiesOptionalParams
  ): Promise<ShareSetPropertiesResponse> {
    const operationArguments: coreHttp.OperationArguments = {
      options: coreHttp.operationOptionsToRequestOptionsBase(options || {})
    };
    return this.client.sendOperationRequest(
      operationArguments,
      setPropertiesOperationSpec
    ) as Promise<ShareSetPropertiesResponse>;
  }

  /**
   * Sets one or more user-defined name-value pairs for the specified share.
   * @param options The options parameters.
   */
  setMetadata(
    options?: ShareSetMetadataOptionalParams
  ): Promise<ShareSetMetadataResponse> {
    const operationArguments: coreHttp.OperationArguments = {
      options: coreHttp.operationOptionsToRequestOptionsBase(options || {})
    };
    return this.client.sendOperationRequest(
      operationArguments,
      setMetadataOperationSpec
    ) as Promise<ShareSetMetadataResponse>;
  }

  /**
   * Returns information about stored access policies specified on the share.
   * @param options The options parameters.
   */
  getAccessPolicy(
    options?: ShareGetAccessPolicyOptionalParams
  ): Promise<ShareGetAccessPolicyResponse> {
    const operationArguments: coreHttp.OperationArguments = {
      options: coreHttp.operationOptionsToRequestOptionsBase(options || {})
    };
    return this.client.sendOperationRequest(
      operationArguments,
      getAccessPolicyOperationSpec
    ) as Promise<ShareGetAccessPolicyResponse>;
  }

  /**
   * Sets a stored access policy for use with shared access signatures.
   * @param options The options parameters.
   */
  setAccessPolicy(
    options?: ShareSetAccessPolicyOptionalParams
  ): Promise<ShareSetAccessPolicyResponse> {
    const operationArguments: coreHttp.OperationArguments = {
      options: coreHttp.operationOptionsToRequestOptionsBase(options || {})
    };
    return this.client.sendOperationRequest(
      operationArguments,
      setAccessPolicyOperationSpec
    ) as Promise<ShareSetAccessPolicyResponse>;
  }

  /**
   * Retrieves statistics related to the share.
   * @param options The options parameters.
   */
  getStatistics(
    options?: ShareGetStatisticsOptionalParams
  ): Promise<ShareGetStatisticsResponse> {
    const operationArguments: coreHttp.OperationArguments = {
      options: coreHttp.operationOptionsToRequestOptionsBase(options || {})
    };
    return this.client.sendOperationRequest(
      operationArguments,
      getStatisticsOperationSpec
    ) as Promise<ShareGetStatisticsResponse>;
  }

  /**
   * Restores a previously deleted Share.
   * @param options The options parameters.
   */
  restore(options?: ShareRestoreOptionalParams): Promise<ShareRestoreResponse> {
    const operationArguments: coreHttp.OperationArguments = {
      options: coreHttp.operationOptionsToRequestOptionsBase(options || {})
    };
    return this.client.sendOperationRequest(
      operationArguments,
      restoreOperationSpec
    ) as Promise<ShareRestoreResponse>;
  }
}
// Operation Specifications
const xmlSerializer = new coreHttp.Serializer(Mappers, /* isXml */ true);

const serializer = new coreHttp.Serializer(Mappers, /* isXml */ false);

const createOperationSpec: coreHttp.OperationSpec = {
  path: "/{shareName}",
  httpMethod: "PUT",
  responses: {
    201: {
      headersMapper: Mappers.ShareCreateHeaders
    },
    default: {
      bodyMapper: Mappers.StorageError,
      headersMapper: Mappers.ShareCreateExceptionHeaders
    }
  },
  queryParameters: [Parameters.timeoutInSeconds, Parameters.restype1],
  urlParameters: [Parameters.url],
  headerParameters: [
    Parameters.version,
    Parameters.accept1,
    Parameters.metadata,
    Parameters.quota,
    Parameters.accessTier,
    Parameters.enabledProtocols,
    Parameters.rootSquash
  ],
  isXML: true,
  serializer: xmlSerializer
};
const getPropertiesOperationSpec: coreHttp.OperationSpec = {
  path: "/{shareName}",
  httpMethod: "GET",
  responses: {
    200: {
      headersMapper: Mappers.ShareGetPropertiesHeaders
    },
    default: {
      bodyMapper: Mappers.StorageError,
      headersMapper: Mappers.ShareGetPropertiesExceptionHeaders
    }
  },
  queryParameters: [
    Parameters.timeoutInSeconds,
    Parameters.restype1,
    Parameters.shareSnapshot
  ],
  urlParameters: [Parameters.url],
  headerParameters: [
    Parameters.version,
    Parameters.accept1,
    Parameters.leaseId
  ],
  isXML: true,
  serializer: xmlSerializer
};
const deleteOperationSpec: coreHttp.OperationSpec = {
  path: "/{shareName}",
  httpMethod: "DELETE",
  responses: {
    202: {
      headersMapper: Mappers.ShareDeleteHeaders
    },
    default: {
      bodyMapper: Mappers.StorageError,
      headersMapper: Mappers.ShareDeleteExceptionHeaders
    }
  },
  queryParameters: [
    Parameters.timeoutInSeconds,
    Parameters.restype1,
    Parameters.shareSnapshot
  ],
  urlParameters: [Parameters.url],
  headerParameters: [
    Parameters.version,
    Parameters.accept1,
    Parameters.leaseId,
    Parameters.deleteSnapshots
  ],
  isXML: true,
  serializer: xmlSerializer
};
const acquireLeaseOperationSpec: coreHttp.OperationSpec = {
  path: "/{shareName}",
  httpMethod: "PUT",
  responses: {
    201: {
      headersMapper: Mappers.ShareAcquireLeaseHeaders
    },
    default: {
      bodyMapper: Mappers.StorageError,
      headersMapper: Mappers.ShareAcquireLeaseExceptionHeaders
    }
  },
  queryParameters: [
    Parameters.timeoutInSeconds,
    Parameters.restype1,
    Parameters.shareSnapshot,
    Parameters.comp2
  ],
  urlParameters: [Parameters.url],
  headerParameters: [
    Parameters.version,
    Parameters.accept1,
    Parameters.action,
    Parameters.duration,
    Parameters.proposedLeaseId,
    Parameters.requestId
  ],
  isXML: true,
  serializer: xmlSerializer
};
const releaseLeaseOperationSpec: coreHttp.OperationSpec = {
  path: "/{shareName}",
  httpMethod: "PUT",
  responses: {
    200: {
      headersMapper: Mappers.ShareReleaseLeaseHeaders
    },
    default: {
      bodyMapper: Mappers.StorageError,
      headersMapper: Mappers.ShareReleaseLeaseExceptionHeaders
    }
  },
  queryParameters: [
    Parameters.timeoutInSeconds,
    Parameters.restype1,
    Parameters.shareSnapshot,
    Parameters.comp2
  ],
  urlParameters: [Parameters.url],
  headerParameters: [
    Parameters.version,
    Parameters.accept1,
    Parameters.requestId,
    Parameters.action1,
    Parameters.leaseId1
  ],
  isXML: true,
  serializer: xmlSerializer
};
const changeLeaseOperationSpec: coreHttp.OperationSpec = {
  path: "/{shareName}",
  httpMethod: "PUT",
  responses: {
    200: {
      headersMapper: Mappers.ShareChangeLeaseHeaders
    },
    default: {
      bodyMapper: Mappers.StorageError,
      headersMapper: Mappers.ShareChangeLeaseExceptionHeaders
    }
  },
  queryParameters: [
    Parameters.timeoutInSeconds,
    Parameters.restype1,
    Parameters.shareSnapshot,
    Parameters.comp2
  ],
  urlParameters: [Parameters.url],
  headerParameters: [
    Parameters.version,
    Parameters.accept1,
    Parameters.proposedLeaseId,
    Parameters.requestId,
    Parameters.leaseId1,
    Parameters.action2
  ],
  isXML: true,
  serializer: xmlSerializer
};
const renewLeaseOperationSpec: coreHttp.OperationSpec = {
  path: "/{shareName}",
  httpMethod: "PUT",
  responses: {
    200: {
      headersMapper: Mappers.ShareRenewLeaseHeaders
    },
    default: {
      bodyMapper: Mappers.StorageError,
      headersMapper: Mappers.ShareRenewLeaseExceptionHeaders
    }
  },
  queryParameters: [
    Parameters.timeoutInSeconds,
    Parameters.restype1,
    Parameters.shareSnapshot,
    Parameters.comp2
  ],
  urlParameters: [Parameters.url],
  headerParameters: [
    Parameters.version,
    Parameters.accept1,
    Parameters.requestId,
    Parameters.leaseId1,
    Parameters.action3
  ],
  isXML: true,
  serializer: xmlSerializer
};
const breakLeaseOperationSpec: coreHttp.OperationSpec = {
  path: "/{shareName}",
  httpMethod: "PUT",
  responses: {
    202: {
      headersMapper: Mappers.ShareBreakLeaseHeaders
    },
    default: {
      bodyMapper: Mappers.StorageError,
      headersMapper: Mappers.ShareBreakLeaseExceptionHeaders
    }
  },
  queryParameters: [
    Parameters.timeoutInSeconds,
    Parameters.restype1,
    Parameters.shareSnapshot,
    Parameters.comp2
  ],
  urlParameters: [Parameters.url],
  headerParameters: [
    Parameters.version,
    Parameters.accept1,
    Parameters.leaseId,
    Parameters.requestId,
    Parameters.action4,
    Parameters.breakPeriod
  ],
  isXML: true,
  serializer: xmlSerializer
};
const createSnapshotOperationSpec: coreHttp.OperationSpec = {
  path: "/{shareName}",
  httpMethod: "PUT",
  responses: {
    201: {
      headersMapper: Mappers.ShareCreateSnapshotHeaders
    },
    default: {
      bodyMapper: Mappers.StorageError,
      headersMapper: Mappers.ShareCreateSnapshotExceptionHeaders
    }
  },
  queryParameters: [
    Parameters.timeoutInSeconds,
    Parameters.restype1,
    Parameters.comp3
  ],
  urlParameters: [Parameters.url],
  headerParameters: [
    Parameters.version,
    Parameters.accept1,
    Parameters.metadata
  ],
  isXML: true,
  serializer: xmlSerializer
};
const createPermissionOperationSpec: coreHttp.OperationSpec = {
  path: "/{shareName}",
  httpMethod: "PUT",
  responses: {
    201: {
      headersMapper: Mappers.ShareCreatePermissionHeaders
    },
    default: {
      bodyMapper: Mappers.StorageError,
      headersMapper: Mappers.ShareCreatePermissionExceptionHeaders
    }
  },
  requestBody: Parameters.sharePermission,
  queryParameters: [
    Parameters.timeoutInSeconds,
    Parameters.restype1,
    Parameters.comp4
  ],
  urlParameters: [Parameters.url],
  headerParameters: [
    Parameters.contentType,
    Parameters.accept,
    Parameters.version
  ],
  isXML: false,
  contentType: "application/xml; charset=utf-8",
  serializer: xmlSerializer
};
const getPermissionOperationSpec: coreHttp.OperationSpec = {
  path: "/{shareName}",
  httpMethod: "GET",
  responses: {
    200: {
      bodyMapper: Mappers.SharePermission,
      headersMapper: Mappers.ShareGetPermissionHeaders
    },
    default: {
      bodyMapper: Mappers.StorageError,
      headersMapper: Mappers.ShareGetPermissionExceptionHeaders
    }
  },
  queryParameters: [
    Parameters.timeoutInSeconds,
    Parameters.restype1,
    Parameters.comp4
  ],
  urlParameters: [Parameters.url],
  headerParameters: [
    Parameters.version,
    Parameters.accept2,
    Parameters.filePermissionKey
  ],
  serializer
};
const setPropertiesOperationSpec: coreHttp.OperationSpec = {
  path: "/{shareName}",
  httpMethod: "PUT",
  responses: {
    200: {
      headersMapper: Mappers.ShareSetPropertiesHeaders
    },
    default: {
      bodyMapper: Mappers.StorageError,
      headersMapper: Mappers.ShareSetPropertiesExceptionHeaders
    }
  },
  queryParameters: [
    Parameters.comp,
    Parameters.timeoutInSeconds,
    Parameters.restype1
  ],
  urlParameters: [Parameters.url],
  headerParameters: [
    Parameters.version,
    Parameters.accept1,
    Parameters.quota,
    Parameters.accessTier,
    Parameters.rootSquash,
    Parameters.leaseId
  ],
  isXML: true,
  serializer: xmlSerializer
};
const setMetadataOperationSpec: coreHttp.OperationSpec = {
  path: "/{shareName}",
  httpMethod: "PUT",
  responses: {
    200: {
      headersMapper: Mappers.ShareSetMetadataHeaders
    },
    default: {
      bodyMapper: Mappers.StorageError,
      headersMapper: Mappers.ShareSetMetadataExceptionHeaders
    }
  },
  queryParameters: [
    Parameters.timeoutInSeconds,
    Parameters.restype1,
    Parameters.comp5
  ],
  urlParameters: [Parameters.url],
  headerParameters: [
    Parameters.version,
    Parameters.accept1,
    Parameters.metadata,
    Parameters.leaseId
  ],
  isXML: true,
  serializer: xmlSerializer
};
const getAccessPolicyOperationSpec: coreHttp.OperationSpec = {
  path: "/{shareName}",
  httpMethod: "GET",
  responses: {
    200: {
      bodyMapper: {
        type: {
          name: "Sequence",
          element: {
            type: { name: "Composite", className: "SignedIdentifier" }
          }
        },
        serializedName: "SignedIdentifiers",
        xmlName: "SignedIdentifiers",
        xmlIsWrapped: true,
        xmlElementName: "SignedIdentifier"
      },
      headersMapper: Mappers.ShareGetAccessPolicyHeaders
    },
    default: {
      bodyMapper: Mappers.StorageError,
      headersMapper: Mappers.ShareGetAccessPolicyExceptionHeaders
    }
  },
  queryParameters: [
    Parameters.timeoutInSeconds,
    Parameters.restype1,
    Parameters.comp6
  ],
  urlParameters: [Parameters.url],
  headerParameters: [
    Parameters.version,
    Parameters.accept1,
    Parameters.leaseId
  ],
  isXML: true,
  serializer: xmlSerializer
};
const setAccessPolicyOperationSpec: coreHttp.OperationSpec = {
  path: "/{shareName}",
  httpMethod: "PUT",
  responses: {
    200: {
      headersMapper: Mappers.ShareSetAccessPolicyHeaders
    },
    default: {
      bodyMapper: Mappers.StorageError,
      headersMapper: Mappers.ShareSetAccessPolicyExceptionHeaders
    }
  },
  requestBody: Parameters.shareAcl,
  queryParameters: [
    Parameters.timeoutInSeconds,
    Parameters.restype1,
    Parameters.comp6
  ],
  urlParameters: [Parameters.url],
  headerParameters: [
    Parameters.contentType,
    Parameters.accept,
    Parameters.version,
    Parameters.leaseId
  ],
  isXML: true,
  contentType: "application/xml; charset=utf-8",
  mediaType: "xml",
  serializer: xmlSerializer
};
const getStatisticsOperationSpec: coreHttp.OperationSpec = {
  path: "/{shareName}",
  httpMethod: "GET",
  responses: {
    200: {
      bodyMapper: Mappers.ShareStats,
      headersMapper: Mappers.ShareGetStatisticsHeaders
    },
    default: {
      bodyMapper: Mappers.StorageError,
      headersMapper: Mappers.ShareGetStatisticsExceptionHeaders
    }
  },
  queryParameters: [
    Parameters.timeoutInSeconds,
    Parameters.restype1,
    Parameters.comp7
  ],
  urlParameters: [Parameters.url],
  headerParameters: [
    Parameters.version,
    Parameters.accept1,
    Parameters.leaseId
  ],
  isXML: true,
  serializer: xmlSerializer
};
const restoreOperationSpec: coreHttp.OperationSpec = {
  path: "/{shareName}",
  httpMethod: "PUT",
  responses: {
    201: {
      headersMapper: Mappers.ShareRestoreHeaders
    },
    default: {
      bodyMapper: Mappers.StorageError,
      headersMapper: Mappers.ShareRestoreExceptionHeaders
    }
  },
  queryParameters: [
    Parameters.timeoutInSeconds,
    Parameters.restype1,
    Parameters.comp8
  ],
  urlParameters: [Parameters.url],
  headerParameters: [
    Parameters.version,
    Parameters.accept1,
    Parameters.requestId,
    Parameters.deletedShareName,
    Parameters.deletedShareVersion
  ],
  isXML: true,
  serializer: xmlSerializer
};
