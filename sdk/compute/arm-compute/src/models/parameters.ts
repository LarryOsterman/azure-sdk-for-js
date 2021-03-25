/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License.
 *
 * Code generated by Microsoft (R) AutoRest Code Generator.
 * Changes may cause incorrect behavior and will be lost if the code is
 * regenerated.
 */

import * as msRest from "@azure/ms-rest-js";

export const acceptLanguage: msRest.OperationParameter = {
  parameterPath: "acceptLanguage",
  mapper: {
    serializedName: "accept-language",
    defaultValue: 'en-US',
    type: {
      name: "String"
    }
  }
};
export const apiVersion0: msRest.OperationQueryParameter = {
  parameterPath: "apiVersion",
  mapper: {
    required: true,
    isConstant: true,
    serializedName: "api-version",
    defaultValue: '2020-12-01',
    type: {
      name: "String"
    }
  }
};
export const apiVersion1: msRest.OperationQueryParameter = {
  parameterPath: "apiVersion",
  mapper: {
    required: true,
    isConstant: true,
    serializedName: "api-version",
    defaultValue: '2019-04-01',
    type: {
      name: "String"
    }
  }
};
export const apiVersion2: msRest.OperationQueryParameter = {
  parameterPath: "apiVersion",
  mapper: {
    required: true,
    isConstant: true,
    serializedName: "api-version",
    defaultValue: '2019-12-01',
    type: {
      name: "String"
    }
  }
};
export const apiVersion3: msRest.OperationQueryParameter = {
  parameterPath: "apiVersion",
  mapper: {
    required: true,
    isConstant: true,
    serializedName: "api-version",
    defaultValue: '2021-03-01',
    type: {
      name: "String"
    }
  }
};
export const availabilitySetName: msRest.OperationURLParameter = {
  parameterPath: "availabilitySetName",
  mapper: {
    required: true,
    serializedName: "availabilitySetName",
    type: {
      name: "String"
    }
  }
};
export const cloudServiceName: msRest.OperationURLParameter = {
  parameterPath: "cloudServiceName",
  mapper: {
    required: true,
    serializedName: "cloudServiceName",
    type: {
      name: "String"
    }
  }
};
export const commandId: msRest.OperationURLParameter = {
  parameterPath: "commandId",
  mapper: {
    required: true,
    serializedName: "commandId",
    type: {
      name: "String"
    }
  }
};
export const diskAccessName: msRest.OperationURLParameter = {
  parameterPath: "diskAccessName",
  mapper: {
    required: true,
    serializedName: "diskAccessName",
    type: {
      name: "String"
    }
  }
};
export const diskEncryptionSetName: msRest.OperationURLParameter = {
  parameterPath: "diskEncryptionSetName",
  mapper: {
    required: true,
    serializedName: "diskEncryptionSetName",
    type: {
      name: "String"
    }
  }
};
export const diskName: msRest.OperationURLParameter = {
  parameterPath: "diskName",
  mapper: {
    required: true,
    serializedName: "diskName",
    type: {
      name: "String"
    }
  }
};
export const diskRestorePointName: msRest.OperationURLParameter = {
  parameterPath: "diskRestorePointName",
  mapper: {
    required: true,
    serializedName: "diskRestorePointName",
    type: {
      name: "String"
    }
  }
};
export const edgeZone: msRest.OperationURLParameter = {
  parameterPath: "edgeZone",
  mapper: {
    required: true,
    serializedName: "edgeZone",
    type: {
      name: "String"
    }
  }
};
export const expand0: msRest.OperationQueryParameter = {
  parameterPath: [
    "options",
    "expand"
  ],
  mapper: {
    serializedName: "$expand",
    type: {
      name: "String"
    }
  }
};
export const expand1: msRest.OperationQueryParameter = {
  parameterPath: [
    "options",
    "expand"
  ],
  mapper: {
    serializedName: "$expand",
    type: {
      name: "Enum",
      allowedValues: [
        "instanceView"
      ]
    }
  }
};
export const filter: msRest.OperationQueryParameter = {
  parameterPath: [
    "options",
    "filter"
  ],
  mapper: {
    serializedName: "$filter",
    type: {
      name: "String"
    }
  }
};
export const forceDeletion: msRest.OperationQueryParameter = {
  parameterPath: [
    "options",
    "forceDeletion"
  ],
  mapper: {
    serializedName: "forceDeletion",
    type: {
      name: "Boolean"
    }
  }
};
export const galleryApplicationName: msRest.OperationURLParameter = {
  parameterPath: "galleryApplicationName",
  mapper: {
    required: true,
    serializedName: "galleryApplicationName",
    type: {
      name: "String"
    }
  }
};
export const galleryApplicationVersionName: msRest.OperationURLParameter = {
  parameterPath: "galleryApplicationVersionName",
  mapper: {
    required: true,
    serializedName: "galleryApplicationVersionName",
    type: {
      name: "String"
    }
  }
};
export const galleryImageName: msRest.OperationURLParameter = {
  parameterPath: "galleryImageName",
  mapper: {
    required: true,
    serializedName: "galleryImageName",
    type: {
      name: "String"
    }
  }
};
export const galleryImageVersionName: msRest.OperationURLParameter = {
  parameterPath: "galleryImageVersionName",
  mapper: {
    required: true,
    serializedName: "galleryImageVersionName",
    type: {
      name: "String"
    }
  }
};
export const galleryName: msRest.OperationURLParameter = {
  parameterPath: "galleryName",
  mapper: {
    required: true,
    serializedName: "galleryName",
    type: {
      name: "String"
    }
  }
};
export const hostGroupName: msRest.OperationURLParameter = {
  parameterPath: "hostGroupName",
  mapper: {
    required: true,
    serializedName: "hostGroupName",
    type: {
      name: "String"
    }
  }
};
export const hostName: msRest.OperationURLParameter = {
  parameterPath: "hostName",
  mapper: {
    required: true,
    serializedName: "hostName",
    type: {
      name: "String"
    }
  }
};
export const imageName: msRest.OperationURLParameter = {
  parameterPath: "imageName",
  mapper: {
    required: true,
    serializedName: "imageName",
    type: {
      name: "String"
    }
  }
};
export const includeColocationStatus: msRest.OperationQueryParameter = {
  parameterPath: [
    "options",
    "includeColocationStatus"
  ],
  mapper: {
    serializedName: "includeColocationStatus",
    type: {
      name: "String"
    }
  }
};
export const instanceId: msRest.OperationURLParameter = {
  parameterPath: "instanceId",
  mapper: {
    required: true,
    serializedName: "instanceId",
    type: {
      name: "String"
    }
  }
};
export const location0: msRest.OperationURLParameter = {
  parameterPath: "location",
  mapper: {
    required: true,
    serializedName: "location",
    type: {
      name: "String"
    }
  }
};
export const location1: msRest.OperationURLParameter = {
  parameterPath: "location",
  mapper: {
    required: true,
    serializedName: "location",
    constraints: {
      Pattern: /^[-\w\._]+$/
    },
    type: {
      name: "String"
    }
  }
};
export const nextPageLink: msRest.OperationURLParameter = {
  parameterPath: "nextPageLink",
  mapper: {
    required: true,
    serializedName: "nextLink",
    type: {
      name: "String"
    }
  },
  skipEncoding: true
};
export const offer: msRest.OperationURLParameter = {
  parameterPath: "offer",
  mapper: {
    required: true,
    serializedName: "offer",
    type: {
      name: "String"
    }
  }
};
export const orderby: msRest.OperationQueryParameter = {
  parameterPath: [
    "options",
    "orderby"
  ],
  mapper: {
    serializedName: "$orderby",
    type: {
      name: "String"
    }
  }
};
export const osFamilyName: msRest.OperationURLParameter = {
  parameterPath: "osFamilyName",
  mapper: {
    required: true,
    serializedName: "osFamilyName",
    type: {
      name: "String"
    }
  }
};
export const osVersionName: msRest.OperationURLParameter = {
  parameterPath: "osVersionName",
  mapper: {
    required: true,
    serializedName: "osVersionName",
    type: {
      name: "String"
    }
  }
};
export const platformUpdateDomain: msRest.OperationQueryParameter = {
  parameterPath: "platformUpdateDomain",
  mapper: {
    required: true,
    serializedName: "platformUpdateDomain",
    type: {
      name: "Number"
    }
  }
};
export const privateEndpointConnectionName: msRest.OperationURLParameter = {
  parameterPath: "privateEndpointConnectionName",
  mapper: {
    required: true,
    serializedName: "privateEndpointConnectionName",
    type: {
      name: "String"
    }
  }
};
export const proximityPlacementGroupName: msRest.OperationURLParameter = {
  parameterPath: "proximityPlacementGroupName",
  mapper: {
    required: true,
    serializedName: "proximityPlacementGroupName",
    type: {
      name: "String"
    }
  }
};
export const publisherName: msRest.OperationURLParameter = {
  parameterPath: "publisherName",
  mapper: {
    required: true,
    serializedName: "publisherName",
    type: {
      name: "String"
    }
  }
};
export const resourceGroupName: msRest.OperationURLParameter = {
  parameterPath: "resourceGroupName",
  mapper: {
    required: true,
    serializedName: "resourceGroupName",
    type: {
      name: "String"
    }
  }
};
export const restorePointCollectionName: msRest.OperationURLParameter = {
  parameterPath: "restorePointCollectionName",
  mapper: {
    required: true,
    serializedName: "restorePointCollectionName",
    type: {
      name: "String"
    }
  }
};
export const roleInstanceName: msRest.OperationURLParameter = {
  parameterPath: "roleInstanceName",
  mapper: {
    required: true,
    serializedName: "roleInstanceName",
    type: {
      name: "String"
    }
  }
};
export const roleName: msRest.OperationURLParameter = {
  parameterPath: "roleName",
  mapper: {
    required: true,
    serializedName: "roleName",
    type: {
      name: "String"
    }
  }
};
export const runCommandName: msRest.OperationURLParameter = {
  parameterPath: "runCommandName",
  mapper: {
    required: true,
    serializedName: "runCommandName",
    type: {
      name: "String"
    }
  }
};
export const sasUriExpirationTimeInMinutes: msRest.OperationQueryParameter = {
  parameterPath: [
    "options",
    "sasUriExpirationTimeInMinutes"
  ],
  mapper: {
    serializedName: "sasUriExpirationTimeInMinutes",
    type: {
      name: "Number"
    }
  }
};
export const select: msRest.OperationQueryParameter = {
  parameterPath: [
    "options",
    "select"
  ],
  mapper: {
    serializedName: "$select",
    type: {
      name: "String"
    }
  }
};
export const skipShutdown: msRest.OperationQueryParameter = {
  parameterPath: [
    "options",
    "skipShutdown"
  ],
  mapper: {
    serializedName: "skipShutdown",
    defaultValue: false,
    type: {
      name: "Boolean"
    }
  }
};
export const skus: msRest.OperationURLParameter = {
  parameterPath: "skus",
  mapper: {
    required: true,
    serializedName: "skus",
    type: {
      name: "String"
    }
  }
};
export const snapshotName: msRest.OperationURLParameter = {
  parameterPath: "snapshotName",
  mapper: {
    required: true,
    serializedName: "snapshotName",
    type: {
      name: "String"
    }
  }
};
export const sshPublicKeyName: msRest.OperationURLParameter = {
  parameterPath: "sshPublicKeyName",
  mapper: {
    required: true,
    serializedName: "sshPublicKeyName",
    type: {
      name: "String"
    }
  }
};
export const statusOnly: msRest.OperationQueryParameter = {
  parameterPath: [
    "options",
    "statusOnly"
  ],
  mapper: {
    serializedName: "statusOnly",
    type: {
      name: "String"
    }
  }
};
export const subscriptionId: msRest.OperationURLParameter = {
  parameterPath: "subscriptionId",
  mapper: {
    required: true,
    serializedName: "subscriptionId",
    type: {
      name: "String"
    }
  }
};
export const top: msRest.OperationQueryParameter = {
  parameterPath: [
    "options",
    "top"
  ],
  mapper: {
    serializedName: "$top",
    type: {
      name: "Number"
    }
  }
};
export const type: msRest.OperationURLParameter = {
  parameterPath: "type",
  mapper: {
    required: true,
    serializedName: "type",
    type: {
      name: "String"
    }
  }
};
export const updateDomain: msRest.OperationURLParameter = {
  parameterPath: "updateDomain",
  mapper: {
    required: true,
    serializedName: "updateDomain",
    type: {
      name: "Number"
    }
  }
};
export const version: msRest.OperationURLParameter = {
  parameterPath: "version",
  mapper: {
    required: true,
    serializedName: "version",
    type: {
      name: "String"
    }
  }
};
export const virtualMachineScaleSetName: msRest.OperationURLParameter = {
  parameterPath: "virtualMachineScaleSetName",
  mapper: {
    required: true,
    serializedName: "virtualMachineScaleSetName",
    type: {
      name: "String"
    }
  }
};
export const vmExtensionName: msRest.OperationURLParameter = {
  parameterPath: "vmExtensionName",
  mapper: {
    required: true,
    serializedName: "vmExtensionName",
    type: {
      name: "String"
    }
  }
};
export const vmName: msRest.OperationURLParameter = {
  parameterPath: "vmName",
  mapper: {
    required: true,
    serializedName: "vmName",
    type: {
      name: "String"
    }
  }
};
export const vmRestorePointName: msRest.OperationURLParameter = {
  parameterPath: "vmRestorePointName",
  mapper: {
    required: true,
    serializedName: "vmRestorePointName",
    type: {
      name: "String"
    }
  }
};
export const vmScaleSetName: msRest.OperationURLParameter = {
  parameterPath: "vmScaleSetName",
  mapper: {
    required: true,
    serializedName: "vmScaleSetName",
    type: {
      name: "String"
    }
  }
};
export const vmssExtensionName: msRest.OperationURLParameter = {
  parameterPath: "vmssExtensionName",
  mapper: {
    required: true,
    serializedName: "vmssExtensionName",
    type: {
      name: "String"
    }
  }
};
