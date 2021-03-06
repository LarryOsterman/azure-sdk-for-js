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
import * as Mappers from "../models/privateLinkResourcesMappers";
import * as Parameters from "../models/parameters";
import { AzureDigitalTwinsManagementClientContext } from "../azureDigitalTwinsManagementClientContext";

/** Class representing a PrivateLinkResources. */
export class PrivateLinkResources {
  private readonly client: AzureDigitalTwinsManagementClientContext;

  /**
   * Create a PrivateLinkResources.
   * @param {AzureDigitalTwinsManagementClientContext} client Reference to the service client.
   */
  constructor(client: AzureDigitalTwinsManagementClientContext) {
    this.client = client;
  }

  /**
   * List private link resources for given Digital Twin.
   * @param resourceGroupName The name of the resource group that contains the DigitalTwinsInstance.
   * @param resourceName The name of the DigitalTwinsInstance.
   * @param [options] The optional parameters
   * @returns Promise<Models.PrivateLinkResourcesListResponse>
   */
  list(resourceGroupName: string, resourceName: string, options?: msRest.RequestOptionsBase): Promise<Models.PrivateLinkResourcesListResponse>;
  /**
   * @param resourceGroupName The name of the resource group that contains the DigitalTwinsInstance.
   * @param resourceName The name of the DigitalTwinsInstance.
   * @param callback The callback
   */
  list(resourceGroupName: string, resourceName: string, callback: msRest.ServiceCallback<Models.GroupIdInformationResponse>): void;
  /**
   * @param resourceGroupName The name of the resource group that contains the DigitalTwinsInstance.
   * @param resourceName The name of the DigitalTwinsInstance.
   * @param options The optional parameters
   * @param callback The callback
   */
  list(resourceGroupName: string, resourceName: string, options: msRest.RequestOptionsBase, callback: msRest.ServiceCallback<Models.GroupIdInformationResponse>): void;
  list(resourceGroupName: string, resourceName: string, options?: msRest.RequestOptionsBase | msRest.ServiceCallback<Models.GroupIdInformationResponse>, callback?: msRest.ServiceCallback<Models.GroupIdInformationResponse>): Promise<Models.PrivateLinkResourcesListResponse> {
    return this.client.sendOperationRequest(
      {
        resourceGroupName,
        resourceName,
        options
      },
      listOperationSpec,
      callback) as Promise<Models.PrivateLinkResourcesListResponse>;
  }

  /**
   * Get the specified private link resource for the given Digital Twin.
   * @param resourceGroupName The name of the resource group that contains the DigitalTwinsInstance.
   * @param resourceName The name of the DigitalTwinsInstance.
   * @param resourceId The name of the private link resource.
   * @param [options] The optional parameters
   * @returns Promise<Models.PrivateLinkResourcesGetResponse>
   */
  get(resourceGroupName: string, resourceName: string, resourceId: string, options?: msRest.RequestOptionsBase): Promise<Models.PrivateLinkResourcesGetResponse>;
  /**
   * @param resourceGroupName The name of the resource group that contains the DigitalTwinsInstance.
   * @param resourceName The name of the DigitalTwinsInstance.
   * @param resourceId The name of the private link resource.
   * @param callback The callback
   */
  get(resourceGroupName: string, resourceName: string, resourceId: string, callback: msRest.ServiceCallback<Models.GroupIdInformation>): void;
  /**
   * @param resourceGroupName The name of the resource group that contains the DigitalTwinsInstance.
   * @param resourceName The name of the DigitalTwinsInstance.
   * @param resourceId The name of the private link resource.
   * @param options The optional parameters
   * @param callback The callback
   */
  get(resourceGroupName: string, resourceName: string, resourceId: string, options: msRest.RequestOptionsBase, callback: msRest.ServiceCallback<Models.GroupIdInformation>): void;
  get(resourceGroupName: string, resourceName: string, resourceId: string, options?: msRest.RequestOptionsBase | msRest.ServiceCallback<Models.GroupIdInformation>, callback?: msRest.ServiceCallback<Models.GroupIdInformation>): Promise<Models.PrivateLinkResourcesGetResponse> {
    return this.client.sendOperationRequest(
      {
        resourceGroupName,
        resourceName,
        resourceId,
        options
      },
      getOperationSpec,
      callback) as Promise<Models.PrivateLinkResourcesGetResponse>;
  }
}

// Operation Specifications
const serializer = new msRest.Serializer(Mappers);
const listOperationSpec: msRest.OperationSpec = {
  httpMethod: "GET",
  path: "subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DigitalTwins/digitalTwinsInstances/{resourceName}/privateLinkResources",
  urlParameters: [
    Parameters.subscriptionId,
    Parameters.resourceGroupName,
    Parameters.resourceName
  ],
  queryParameters: [
    Parameters.apiVersion
  ],
  headerParameters: [
    Parameters.acceptLanguage
  ],
  responses: {
    200: {
      bodyMapper: Mappers.GroupIdInformationResponse
    },
    default: {
      bodyMapper: Mappers.ErrorResponse
    }
  },
  serializer
};

const getOperationSpec: msRest.OperationSpec = {
  httpMethod: "GET",
  path: "subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DigitalTwins/digitalTwinsInstances/{resourceName}/privateLinkResources/{resourceId}",
  urlParameters: [
    Parameters.subscriptionId,
    Parameters.resourceGroupName,
    Parameters.resourceName,
    Parameters.resourceId
  ],
  queryParameters: [
    Parameters.apiVersion
  ],
  headerParameters: [
    Parameters.acceptLanguage
  ],
  responses: {
    200: {
      bodyMapper: Mappers.GroupIdInformation
    },
    default: {
      bodyMapper: Mappers.ErrorResponse
    }
  },
  serializer
};
