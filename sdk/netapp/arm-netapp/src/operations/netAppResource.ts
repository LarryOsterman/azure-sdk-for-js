/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License.
 *
 * Code generated by Microsoft (R) AutoRest Code Generator.
 * Changes may cause incorrect behavior and will be lost if the code is
 * regenerated.
 */

import * as msRest from "@azure/ms-rest-js";
import * as Models from "../models";
import * as Mappers from "../models/netAppResourceMappers";
import * as Parameters from "../models/parameters";
import { AzureNetAppFilesManagementClientContext } from "../azureNetAppFilesManagementClientContext";

/** Class representing a NetAppResource. */
export class NetAppResource {
  private readonly client: AzureNetAppFilesManagementClientContext;

  /**
   * Create a NetAppResource.
   * @param {AzureNetAppFilesManagementClientContext} client Reference to the service client.
   */
  constructor(client: AzureNetAppFilesManagementClientContext) {
    this.client = client;
  }

  /**
   * Check if a resource name is available.
   * @summary Check resource name availability
   * @param location The location
   * @param name Resource name to verify.
   * @param type Resource type used for verification. Possible values include:
   * 'Microsoft.NetApp/netAppAccounts', 'Microsoft.NetApp/netAppAccounts/capacityPools',
   * 'Microsoft.NetApp/netAppAccounts/capacityPools/volumes',
   * 'Microsoft.NetApp/netAppAccounts/capacityPools/volumes/snapshots'
   * @param resourceGroup Resource group name.
   * @param [options] The optional parameters
   * @returns Promise<Models.NetAppResourceCheckNameAvailabilityResponse>
   */
  checkNameAvailability(location: string, name: string, type: Models.CheckNameResourceTypes, resourceGroup: string, options?: msRest.RequestOptionsBase): Promise<Models.NetAppResourceCheckNameAvailabilityResponse>;
  /**
   * @param location The location
   * @param name Resource name to verify.
   * @param type Resource type used for verification. Possible values include:
   * 'Microsoft.NetApp/netAppAccounts', 'Microsoft.NetApp/netAppAccounts/capacityPools',
   * 'Microsoft.NetApp/netAppAccounts/capacityPools/volumes',
   * 'Microsoft.NetApp/netAppAccounts/capacityPools/volumes/snapshots'
   * @param resourceGroup Resource group name.
   * @param callback The callback
   */
  checkNameAvailability(location: string, name: string, type: Models.CheckNameResourceTypes, resourceGroup: string, callback: msRest.ServiceCallback<Models.CheckAvailabilityResponse>): void;
  /**
   * @param location The location
   * @param name Resource name to verify.
   * @param type Resource type used for verification. Possible values include:
   * 'Microsoft.NetApp/netAppAccounts', 'Microsoft.NetApp/netAppAccounts/capacityPools',
   * 'Microsoft.NetApp/netAppAccounts/capacityPools/volumes',
   * 'Microsoft.NetApp/netAppAccounts/capacityPools/volumes/snapshots'
   * @param resourceGroup Resource group name.
   * @param options The optional parameters
   * @param callback The callback
   */
  checkNameAvailability(location: string, name: string, type: Models.CheckNameResourceTypes, resourceGroup: string, options: msRest.RequestOptionsBase, callback: msRest.ServiceCallback<Models.CheckAvailabilityResponse>): void;
  checkNameAvailability(location: string, name: string, type: Models.CheckNameResourceTypes, resourceGroup: string, options?: msRest.RequestOptionsBase | msRest.ServiceCallback<Models.CheckAvailabilityResponse>, callback?: msRest.ServiceCallback<Models.CheckAvailabilityResponse>): Promise<Models.NetAppResourceCheckNameAvailabilityResponse> {
    return this.client.sendOperationRequest(
      {
        location,
        name,
        type,
        resourceGroup,
        options
      },
      checkNameAvailabilityOperationSpec,
      callback) as Promise<Models.NetAppResourceCheckNameAvailabilityResponse>;
  }

  /**
   * Check if a file path is available.
   * @summary Check file path availability
   * @param location The location
   * @param name File path to verify.
   * @param subnetId The Azure Resource URI for a delegated subnet. Must have the delegation
   * Microsoft.NetApp/volumes
   * @param [options] The optional parameters
   * @returns Promise<Models.NetAppResourceCheckFilePathAvailabilityResponse>
   */
  checkFilePathAvailability(location: string, name: string, subnetId: string, options?: msRest.RequestOptionsBase): Promise<Models.NetAppResourceCheckFilePathAvailabilityResponse>;
  /**
   * @param location The location
   * @param name File path to verify.
   * @param subnetId The Azure Resource URI for a delegated subnet. Must have the delegation
   * Microsoft.NetApp/volumes
   * @param callback The callback
   */
  checkFilePathAvailability(location: string, name: string, subnetId: string, callback: msRest.ServiceCallback<Models.CheckAvailabilityResponse>): void;
  /**
   * @param location The location
   * @param name File path to verify.
   * @param subnetId The Azure Resource URI for a delegated subnet. Must have the delegation
   * Microsoft.NetApp/volumes
   * @param options The optional parameters
   * @param callback The callback
   */
  checkFilePathAvailability(location: string, name: string, subnetId: string, options: msRest.RequestOptionsBase, callback: msRest.ServiceCallback<Models.CheckAvailabilityResponse>): void;
  checkFilePathAvailability(location: string, name: string, subnetId: string, options?: msRest.RequestOptionsBase | msRest.ServiceCallback<Models.CheckAvailabilityResponse>, callback?: msRest.ServiceCallback<Models.CheckAvailabilityResponse>): Promise<Models.NetAppResourceCheckFilePathAvailabilityResponse> {
    return this.client.sendOperationRequest(
      {
        location,
        name,
        subnetId,
        options
      },
      checkFilePathAvailabilityOperationSpec,
      callback) as Promise<Models.NetAppResourceCheckFilePathAvailabilityResponse>;
  }

  /**
   * Check if a quota is available.
   * @summary Check quota availability
   * @param location The location
   * @param name Name of the resource to verify.
   * @param type Resource type used for verification. Possible values include:
   * 'Microsoft.NetApp/netAppAccounts', 'Microsoft.NetApp/netAppAccounts/capacityPools',
   * 'Microsoft.NetApp/netAppAccounts/capacityPools/volumes',
   * 'Microsoft.NetApp/netAppAccounts/capacityPools/volumes/snapshots'
   * @param resourceGroup Resource group name.
   * @param [options] The optional parameters
   * @returns Promise<Models.NetAppResourceCheckQuotaAvailabilityResponse>
   */
  checkQuotaAvailability(location: string, name: string, type: Models.CheckQuotaNameResourceTypes, resourceGroup: string, options?: msRest.RequestOptionsBase): Promise<Models.NetAppResourceCheckQuotaAvailabilityResponse>;
  /**
   * @param location The location
   * @param name Name of the resource to verify.
   * @param type Resource type used for verification. Possible values include:
   * 'Microsoft.NetApp/netAppAccounts', 'Microsoft.NetApp/netAppAccounts/capacityPools',
   * 'Microsoft.NetApp/netAppAccounts/capacityPools/volumes',
   * 'Microsoft.NetApp/netAppAccounts/capacityPools/volumes/snapshots'
   * @param resourceGroup Resource group name.
   * @param callback The callback
   */
  checkQuotaAvailability(location: string, name: string, type: Models.CheckQuotaNameResourceTypes, resourceGroup: string, callback: msRest.ServiceCallback<Models.CheckAvailabilityResponse>): void;
  /**
   * @param location The location
   * @param name Name of the resource to verify.
   * @param type Resource type used for verification. Possible values include:
   * 'Microsoft.NetApp/netAppAccounts', 'Microsoft.NetApp/netAppAccounts/capacityPools',
   * 'Microsoft.NetApp/netAppAccounts/capacityPools/volumes',
   * 'Microsoft.NetApp/netAppAccounts/capacityPools/volumes/snapshots'
   * @param resourceGroup Resource group name.
   * @param options The optional parameters
   * @param callback The callback
   */
  checkQuotaAvailability(location: string, name: string, type: Models.CheckQuotaNameResourceTypes, resourceGroup: string, options: msRest.RequestOptionsBase, callback: msRest.ServiceCallback<Models.CheckAvailabilityResponse>): void;
  checkQuotaAvailability(location: string, name: string, type: Models.CheckQuotaNameResourceTypes, resourceGroup: string, options?: msRest.RequestOptionsBase | msRest.ServiceCallback<Models.CheckAvailabilityResponse>, callback?: msRest.ServiceCallback<Models.CheckAvailabilityResponse>): Promise<Models.NetAppResourceCheckQuotaAvailabilityResponse> {
    return this.client.sendOperationRequest(
      {
        location,
        name,
        type,
        resourceGroup,
        options
      },
      checkQuotaAvailabilityOperationSpec,
      callback) as Promise<Models.NetAppResourceCheckQuotaAvailabilityResponse>;
  }
}

// Operation Specifications
const serializer = new msRest.Serializer(Mappers);
const checkNameAvailabilityOperationSpec: msRest.OperationSpec = {
  httpMethod: "POST",
  path: "subscriptions/{subscriptionId}/providers/Microsoft.NetApp/locations/{location}/checkNameAvailability",
  urlParameters: [
    Parameters.subscriptionId,
    Parameters.location
  ],
  queryParameters: [
    Parameters.apiVersion
  ],
  headerParameters: [
    Parameters.acceptLanguage
  ],
  requestBody: {
    parameterPath: {
      name: "name",
      type: "type",
      resourceGroup: "resourceGroup"
    },
    mapper: {
      ...Mappers.ResourceNameAvailabilityRequest,
      required: true
    }
  },
  responses: {
    200: {
      bodyMapper: Mappers.CheckAvailabilityResponse
    },
    default: {
      bodyMapper: Mappers.CloudError
    }
  },
  serializer
};

const checkFilePathAvailabilityOperationSpec: msRest.OperationSpec = {
  httpMethod: "POST",
  path: "subscriptions/{subscriptionId}/providers/Microsoft.NetApp/locations/{location}/checkFilePathAvailability",
  urlParameters: [
    Parameters.subscriptionId,
    Parameters.location
  ],
  queryParameters: [
    Parameters.apiVersion
  ],
  headerParameters: [
    Parameters.acceptLanguage
  ],
  requestBody: {
    parameterPath: {
      name: "name",
      subnetId: "subnetId"
    },
    mapper: {
      ...Mappers.FilePathAvailabilityRequest,
      required: true
    }
  },
  responses: {
    200: {
      bodyMapper: Mappers.CheckAvailabilityResponse
    },
    default: {
      bodyMapper: Mappers.CloudError
    }
  },
  serializer
};

const checkQuotaAvailabilityOperationSpec: msRest.OperationSpec = {
  httpMethod: "POST",
  path: "subscriptions/{subscriptionId}/providers/Microsoft.NetApp/locations/{location}/checkQuotaAvailability",
  urlParameters: [
    Parameters.subscriptionId,
    Parameters.location
  ],
  queryParameters: [
    Parameters.apiVersion
  ],
  headerParameters: [
    Parameters.acceptLanguage
  ],
  requestBody: {
    parameterPath: {
      name: "name",
      type: "type",
      resourceGroup: "resourceGroup"
    },
    mapper: {
      ...Mappers.QuotaAvailabilityRequest,
      required: true
    }
  },
  responses: {
    200: {
      bodyMapper: Mappers.CheckAvailabilityResponse
    },
    default: {
      bodyMapper: Mappers.CloudError
    }
  },
  serializer
};
