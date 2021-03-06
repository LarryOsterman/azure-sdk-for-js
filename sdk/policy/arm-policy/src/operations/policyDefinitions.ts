/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License.
 *
 * Code generated by Microsoft (R) AutoRest Code Generator.
 * Changes may cause incorrect behavior and will be lost if the code is regenerated.
 */

import "@azure/core-paging";
import { PagedAsyncIterableIterator } from "@azure/core-paging";
import { PolicyDefinitions } from "../operationsInterfaces";
import * as coreClient from "@azure/core-client";
import * as Mappers from "../models/mappers";
import * as Parameters from "../models/parameters";
import { PolicyClientContext } from "../policyClientContext";
import {
  PolicyDefinition,
  PolicyDefinitionsListNextOptionalParams,
  PolicyDefinitionsListOptionalParams,
  PolicyDefinitionsListBuiltInNextOptionalParams,
  PolicyDefinitionsListBuiltInOptionalParams,
  PolicyDefinitionsListByManagementGroupNextOptionalParams,
  PolicyDefinitionsListByManagementGroupOptionalParams,
  PolicyDefinitionsListNextNextOptionalParams,
  PolicyDefinitionsListBuiltInNextNextOptionalParams,
  PolicyDefinitionsListByManagementGroupNextNextOptionalParams,
  PolicyDefinitionsCreateOrUpdateOptionalParams,
  PolicyDefinitionsCreateOrUpdateResponse,
  PolicyDefinitionsDeleteOptionalParams,
  PolicyDefinitionsGetOptionalParams,
  PolicyDefinitionsGetResponse,
  PolicyDefinitionsGetBuiltInOptionalParams,
  PolicyDefinitionsGetBuiltInResponse,
  PolicyDefinitionsCreateOrUpdateAtManagementGroupOptionalParams,
  PolicyDefinitionsCreateOrUpdateAtManagementGroupResponse,
  PolicyDefinitionsDeleteAtManagementGroupOptionalParams,
  PolicyDefinitionsGetAtManagementGroupOptionalParams,
  PolicyDefinitionsGetAtManagementGroupResponse,
  PolicyDefinitionsListResponse,
  PolicyDefinitionsListBuiltInResponse,
  PolicyDefinitionsListByManagementGroupResponse,
  PolicyDefinitionsListNextResponse,
  PolicyDefinitionsListBuiltInNextResponse,
  PolicyDefinitionsListByManagementGroupNextResponse,
  PolicyDefinitionsListNextNextResponse,
  PolicyDefinitionsListBuiltInNextNextResponse,
  PolicyDefinitionsListByManagementGroupNextNextResponse
} from "../models";

/// <reference lib="esnext.asynciterable" />
/** Class representing a PolicyDefinitions. */
export class PolicyDefinitionsImpl implements PolicyDefinitions {
  private readonly client: PolicyClientContext;

  /**
   * Initialize a new instance of the class PolicyDefinitions class.
   * @param client Reference to the service client
   */
  constructor(client: PolicyClientContext) {
    this.client = client;
  }

  /**
   * This operation retrieves a list of all the policy definitions in a given subscription that match the
   * optional given $filter. Valid values for $filter are: 'atExactScope()', 'policyType -eq {value}' or
   * 'category eq '{value}''. If $filter is not provided, the unfiltered list includes all policy
   * definitions associated with the subscription, including those that apply directly or from management
   * groups that contain the given subscription. If $filter=atExactScope() is provided, the returned list
   * only includes all policy definitions that at the given subscription. If $filter='policyType -eq
   * {value}' is provided, the returned list only includes all policy definitions whose type match the
   * {value}. Possible policyType values are NotSpecified, BuiltIn, Custom, and Static. If
   * $filter='category -eq {value}' is provided, the returned list only includes all policy definitions
   * whose category match the {value}.
   * @param options The options parameters.
   */
  public list(
    options?: PolicyDefinitionsListOptionalParams
  ): PagedAsyncIterableIterator<PolicyDefinition> {
    const iter = this.listPagingAll(options);
    return {
      next() {
        return iter.next();
      },
      [Symbol.asyncIterator]() {
        return this;
      },
      byPage: () => {
        return this.listPagingPage(options);
      }
    };
  }

  private async *listPagingPage(
    options?: PolicyDefinitionsListOptionalParams
  ): AsyncIterableIterator<PolicyDefinition[]> {
    let result = await this._list(options);
    yield result.value || [];
    let continuationToken = result.nextLink;
    while (continuationToken) {
      result = await this._listNext(continuationToken, options);
      continuationToken = result.nextLink;
      yield result.value || [];
    }
  }

  private async *listPagingAll(
    options?: PolicyDefinitionsListOptionalParams
  ): AsyncIterableIterator<PolicyDefinition> {
    for await (const page of this.listPagingPage(options)) {
      yield* page;
    }
  }

  /**
   * This operation retrieves a list of all the built-in policy definitions that match the optional given
   * $filter. If $filter='policyType -eq {value}' is provided, the returned list only includes all
   * built-in policy definitions whose type match the {value}. Possible policyType values are
   * NotSpecified, BuiltIn, Custom, and Static. If $filter='category -eq {value}' is provided, the
   * returned list only includes all built-in policy definitions whose category match the {value}.
   * @param options The options parameters.
   */
  public listBuiltIn(
    options?: PolicyDefinitionsListBuiltInOptionalParams
  ): PagedAsyncIterableIterator<PolicyDefinition> {
    const iter = this.listBuiltInPagingAll(options);
    return {
      next() {
        return iter.next();
      },
      [Symbol.asyncIterator]() {
        return this;
      },
      byPage: () => {
        return this.listBuiltInPagingPage(options);
      }
    };
  }

  private async *listBuiltInPagingPage(
    options?: PolicyDefinitionsListBuiltInOptionalParams
  ): AsyncIterableIterator<PolicyDefinition[]> {
    let result = await this._listBuiltIn(options);
    yield result.value || [];
    let continuationToken = result.nextLink;
    while (continuationToken) {
      result = await this._listBuiltInNext(continuationToken, options);
      continuationToken = result.nextLink;
      yield result.value || [];
    }
  }

  private async *listBuiltInPagingAll(
    options?: PolicyDefinitionsListBuiltInOptionalParams
  ): AsyncIterableIterator<PolicyDefinition> {
    for await (const page of this.listBuiltInPagingPage(options)) {
      yield* page;
    }
  }

  /**
   * This operation retrieves a list of all the policy definitions in a given management group that match
   * the optional given $filter. Valid values for $filter are: 'atExactScope()', 'policyType -eq {value}'
   * or 'category eq '{value}''. If $filter is not provided, the unfiltered list includes all policy
   * definitions associated with the management group, including those that apply directly or from
   * management groups that contain the given management group. If $filter=atExactScope() is provided,
   * the returned list only includes all policy definitions that at the given management group. If
   * $filter='policyType -eq {value}' is provided, the returned list only includes all policy definitions
   * whose type match the {value}. Possible policyType values are NotSpecified, BuiltIn, Custom, and
   * Static. If $filter='category -eq {value}' is provided, the returned list only includes all policy
   * definitions whose category match the {value}.
   * @param managementGroupId The ID of the management group.
   * @param options The options parameters.
   */
  public listByManagementGroup(
    managementGroupId: string,
    options?: PolicyDefinitionsListByManagementGroupOptionalParams
  ): PagedAsyncIterableIterator<PolicyDefinition> {
    const iter = this.listByManagementGroupPagingAll(
      managementGroupId,
      options
    );
    return {
      next() {
        return iter.next();
      },
      [Symbol.asyncIterator]() {
        return this;
      },
      byPage: () => {
        return this.listByManagementGroupPagingPage(managementGroupId, options);
      }
    };
  }

  private async *listByManagementGroupPagingPage(
    managementGroupId: string,
    options?: PolicyDefinitionsListByManagementGroupOptionalParams
  ): AsyncIterableIterator<PolicyDefinition[]> {
    let result = await this._listByManagementGroup(managementGroupId, options);
    yield result.value || [];
    let continuationToken = result.nextLink;
    while (continuationToken) {
      result = await this._listByManagementGroupNext(
        managementGroupId,
        continuationToken,
        options
      );
      continuationToken = result.nextLink;
      yield result.value || [];
    }
  }

  private async *listByManagementGroupPagingAll(
    managementGroupId: string,
    options?: PolicyDefinitionsListByManagementGroupOptionalParams
  ): AsyncIterableIterator<PolicyDefinition> {
    for await (const page of this.listByManagementGroupPagingPage(
      managementGroupId,
      options
    )) {
      yield* page;
    }
  }

  /**
   * ListNext
   * @param nextLink The nextLink from the previous successful call to the List method.
   * @param options The options parameters.
   */
  public listNext(
    nextLink: string,
    options?: PolicyDefinitionsListNextOptionalParams
  ): PagedAsyncIterableIterator<PolicyDefinition> {
    const iter = this.listNextPagingAll(nextLink, options);
    return {
      next() {
        return iter.next();
      },
      [Symbol.asyncIterator]() {
        return this;
      },
      byPage: () => {
        return this.listNextPagingPage(nextLink, options);
      }
    };
  }

  private async *listNextPagingPage(
    nextLink: string,
    options?: PolicyDefinitionsListNextOptionalParams
  ): AsyncIterableIterator<PolicyDefinition[]> {
    let result = await this._listNext(nextLink, options);
    yield result.value || [];
    let continuationToken = result.nextLink;
    while (continuationToken) {
      result = await this._listNextNext(continuationToken, options);
      continuationToken = result.nextLink;
      yield result.value || [];
    }
  }

  private async *listNextPagingAll(
    nextLink: string,
    options?: PolicyDefinitionsListNextOptionalParams
  ): AsyncIterableIterator<PolicyDefinition> {
    for await (const page of this.listNextPagingPage(nextLink, options)) {
      yield* page;
    }
  }

  /**
   * ListBuiltInNext
   * @param nextLink The nextLink from the previous successful call to the ListBuiltIn method.
   * @param options The options parameters.
   */
  public listBuiltInNext(
    nextLink: string,
    options?: PolicyDefinitionsListBuiltInNextOptionalParams
  ): PagedAsyncIterableIterator<PolicyDefinition> {
    const iter = this.listBuiltInNextPagingAll(nextLink, options);
    return {
      next() {
        return iter.next();
      },
      [Symbol.asyncIterator]() {
        return this;
      },
      byPage: () => {
        return this.listBuiltInNextPagingPage(nextLink, options);
      }
    };
  }

  private async *listBuiltInNextPagingPage(
    nextLink: string,
    options?: PolicyDefinitionsListBuiltInNextOptionalParams
  ): AsyncIterableIterator<PolicyDefinition[]> {
    let result = await this._listBuiltInNext(nextLink, options);
    yield result.value || [];
    let continuationToken = result.nextLink;
    while (continuationToken) {
      result = await this._listBuiltInNextNext(continuationToken, options);
      continuationToken = result.nextLink;
      yield result.value || [];
    }
  }

  private async *listBuiltInNextPagingAll(
    nextLink: string,
    options?: PolicyDefinitionsListBuiltInNextOptionalParams
  ): AsyncIterableIterator<PolicyDefinition> {
    for await (const page of this.listBuiltInNextPagingPage(
      nextLink,
      options
    )) {
      yield* page;
    }
  }

  /**
   * ListByManagementGroupNext
   * @param managementGroupId The ID of the management group.
   * @param nextLink The nextLink from the previous successful call to the ListByManagementGroup method.
   * @param options The options parameters.
   */
  public listByManagementGroupNext(
    managementGroupId: string,
    nextLink: string,
    options?: PolicyDefinitionsListByManagementGroupNextOptionalParams
  ): PagedAsyncIterableIterator<PolicyDefinition> {
    const iter = this.listByManagementGroupNextPagingAll(
      managementGroupId,
      nextLink,
      options
    );
    return {
      next() {
        return iter.next();
      },
      [Symbol.asyncIterator]() {
        return this;
      },
      byPage: () => {
        return this.listByManagementGroupNextPagingPage(
          managementGroupId,
          nextLink,
          options
        );
      }
    };
  }

  private async *listByManagementGroupNextPagingPage(
    managementGroupId: string,
    nextLink: string,
    options?: PolicyDefinitionsListByManagementGroupNextOptionalParams
  ): AsyncIterableIterator<PolicyDefinition[]> {
    let result = await this._listByManagementGroupNext(
      managementGroupId,
      nextLink,
      options
    );
    yield result.value || [];
    let continuationToken = result.nextLink;
    while (continuationToken) {
      result = await this._listByManagementGroupNextNext(
        managementGroupId,
        continuationToken,
        options
      );
      continuationToken = result.nextLink;
      yield result.value || [];
    }
  }

  private async *listByManagementGroupNextPagingAll(
    managementGroupId: string,
    nextLink: string,
    options?: PolicyDefinitionsListByManagementGroupNextOptionalParams
  ): AsyncIterableIterator<PolicyDefinition> {
    for await (const page of this.listByManagementGroupNextPagingPage(
      managementGroupId,
      nextLink,
      options
    )) {
      yield* page;
    }
  }

  /**
   * This operation creates or updates a policy definition in the given subscription with the given name.
   * @param policyDefinitionName The name of the policy definition to create.
   * @param parameters The policy definition properties.
   * @param options The options parameters.
   */
  createOrUpdate(
    policyDefinitionName: string,
    parameters: PolicyDefinition,
    options?: PolicyDefinitionsCreateOrUpdateOptionalParams
  ): Promise<PolicyDefinitionsCreateOrUpdateResponse> {
    return this.client.sendOperationRequest(
      { policyDefinitionName, parameters, options },
      createOrUpdateOperationSpec
    );
  }

  /**
   * This operation deletes the policy definition in the given subscription with the given name.
   * @param policyDefinitionName The name of the policy definition to delete.
   * @param options The options parameters.
   */
  delete(
    policyDefinitionName: string,
    options?: PolicyDefinitionsDeleteOptionalParams
  ): Promise<void> {
    return this.client.sendOperationRequest(
      { policyDefinitionName, options },
      deleteOperationSpec
    );
  }

  /**
   * This operation retrieves the policy definition in the given subscription with the given name.
   * @param policyDefinitionName The name of the policy definition to get.
   * @param options The options parameters.
   */
  get(
    policyDefinitionName: string,
    options?: PolicyDefinitionsGetOptionalParams
  ): Promise<PolicyDefinitionsGetResponse> {
    return this.client.sendOperationRequest(
      { policyDefinitionName, options },
      getOperationSpec
    );
  }

  /**
   * This operation retrieves the built-in policy definition with the given name.
   * @param policyDefinitionName The name of the built-in policy definition to get.
   * @param options The options parameters.
   */
  getBuiltIn(
    policyDefinitionName: string,
    options?: PolicyDefinitionsGetBuiltInOptionalParams
  ): Promise<PolicyDefinitionsGetBuiltInResponse> {
    return this.client.sendOperationRequest(
      { policyDefinitionName, options },
      getBuiltInOperationSpec
    );
  }

  /**
   * This operation creates or updates a policy definition in the given management group with the given
   * name.
   * @param policyDefinitionName The name of the policy definition to create.
   * @param managementGroupId The ID of the management group.
   * @param parameters The policy definition properties.
   * @param options The options parameters.
   */
  createOrUpdateAtManagementGroup(
    policyDefinitionName: string,
    managementGroupId: string,
    parameters: PolicyDefinition,
    options?: PolicyDefinitionsCreateOrUpdateAtManagementGroupOptionalParams
  ): Promise<PolicyDefinitionsCreateOrUpdateAtManagementGroupResponse> {
    return this.client.sendOperationRequest(
      { policyDefinitionName, managementGroupId, parameters, options },
      createOrUpdateAtManagementGroupOperationSpec
    );
  }

  /**
   * This operation deletes the policy definition in the given management group with the given name.
   * @param policyDefinitionName The name of the policy definition to delete.
   * @param managementGroupId The ID of the management group.
   * @param options The options parameters.
   */
  deleteAtManagementGroup(
    policyDefinitionName: string,
    managementGroupId: string,
    options?: PolicyDefinitionsDeleteAtManagementGroupOptionalParams
  ): Promise<void> {
    return this.client.sendOperationRequest(
      { policyDefinitionName, managementGroupId, options },
      deleteAtManagementGroupOperationSpec
    );
  }

  /**
   * This operation retrieves the policy definition in the given management group with the given name.
   * @param policyDefinitionName The name of the policy definition to get.
   * @param managementGroupId The ID of the management group.
   * @param options The options parameters.
   */
  getAtManagementGroup(
    policyDefinitionName: string,
    managementGroupId: string,
    options?: PolicyDefinitionsGetAtManagementGroupOptionalParams
  ): Promise<PolicyDefinitionsGetAtManagementGroupResponse> {
    return this.client.sendOperationRequest(
      { policyDefinitionName, managementGroupId, options },
      getAtManagementGroupOperationSpec
    );
  }

  /**
   * This operation retrieves a list of all the policy definitions in a given subscription that match the
   * optional given $filter. Valid values for $filter are: 'atExactScope()', 'policyType -eq {value}' or
   * 'category eq '{value}''. If $filter is not provided, the unfiltered list includes all policy
   * definitions associated with the subscription, including those that apply directly or from management
   * groups that contain the given subscription. If $filter=atExactScope() is provided, the returned list
   * only includes all policy definitions that at the given subscription. If $filter='policyType -eq
   * {value}' is provided, the returned list only includes all policy definitions whose type match the
   * {value}. Possible policyType values are NotSpecified, BuiltIn, Custom, and Static. If
   * $filter='category -eq {value}' is provided, the returned list only includes all policy definitions
   * whose category match the {value}.
   * @param options The options parameters.
   */
  private _list(
    options?: PolicyDefinitionsListOptionalParams
  ): Promise<PolicyDefinitionsListResponse> {
    return this.client.sendOperationRequest({ options }, listOperationSpec);
  }

  /**
   * This operation retrieves a list of all the built-in policy definitions that match the optional given
   * $filter. If $filter='policyType -eq {value}' is provided, the returned list only includes all
   * built-in policy definitions whose type match the {value}. Possible policyType values are
   * NotSpecified, BuiltIn, Custom, and Static. If $filter='category -eq {value}' is provided, the
   * returned list only includes all built-in policy definitions whose category match the {value}.
   * @param options The options parameters.
   */
  private _listBuiltIn(
    options?: PolicyDefinitionsListBuiltInOptionalParams
  ): Promise<PolicyDefinitionsListBuiltInResponse> {
    return this.client.sendOperationRequest(
      { options },
      listBuiltInOperationSpec
    );
  }

  /**
   * This operation retrieves a list of all the policy definitions in a given management group that match
   * the optional given $filter. Valid values for $filter are: 'atExactScope()', 'policyType -eq {value}'
   * or 'category eq '{value}''. If $filter is not provided, the unfiltered list includes all policy
   * definitions associated with the management group, including those that apply directly or from
   * management groups that contain the given management group. If $filter=atExactScope() is provided,
   * the returned list only includes all policy definitions that at the given management group. If
   * $filter='policyType -eq {value}' is provided, the returned list only includes all policy definitions
   * whose type match the {value}. Possible policyType values are NotSpecified, BuiltIn, Custom, and
   * Static. If $filter='category -eq {value}' is provided, the returned list only includes all policy
   * definitions whose category match the {value}.
   * @param managementGroupId The ID of the management group.
   * @param options The options parameters.
   */
  private _listByManagementGroup(
    managementGroupId: string,
    options?: PolicyDefinitionsListByManagementGroupOptionalParams
  ): Promise<PolicyDefinitionsListByManagementGroupResponse> {
    return this.client.sendOperationRequest(
      { managementGroupId, options },
      listByManagementGroupOperationSpec
    );
  }

  /**
   * ListNext
   * @param nextLink The nextLink from the previous successful call to the List method.
   * @param options The options parameters.
   */
  private _listNext(
    nextLink: string,
    options?: PolicyDefinitionsListNextOptionalParams
  ): Promise<PolicyDefinitionsListNextResponse> {
    return this.client.sendOperationRequest(
      { nextLink, options },
      listNextOperationSpec
    );
  }

  /**
   * ListBuiltInNext
   * @param nextLink The nextLink from the previous successful call to the ListBuiltIn method.
   * @param options The options parameters.
   */
  private _listBuiltInNext(
    nextLink: string,
    options?: PolicyDefinitionsListBuiltInNextOptionalParams
  ): Promise<PolicyDefinitionsListBuiltInNextResponse> {
    return this.client.sendOperationRequest(
      { nextLink, options },
      listBuiltInNextOperationSpec
    );
  }

  /**
   * ListByManagementGroupNext
   * @param managementGroupId The ID of the management group.
   * @param nextLink The nextLink from the previous successful call to the ListByManagementGroup method.
   * @param options The options parameters.
   */
  private _listByManagementGroupNext(
    managementGroupId: string,
    nextLink: string,
    options?: PolicyDefinitionsListByManagementGroupNextOptionalParams
  ): Promise<PolicyDefinitionsListByManagementGroupNextResponse> {
    return this.client.sendOperationRequest(
      { managementGroupId, nextLink, options },
      listByManagementGroupNextOperationSpec
    );
  }

  /**
   * ListNextNext
   * @param nextLink The nextLink from the previous successful call to the ListNext method.
   * @param options The options parameters.
   */
  private _listNextNext(
    nextLink: string,
    options?: PolicyDefinitionsListNextNextOptionalParams
  ): Promise<PolicyDefinitionsListNextNextResponse> {
    return this.client.sendOperationRequest(
      { nextLink, options },
      listNextNextOperationSpec
    );
  }

  /**
   * ListBuiltInNextNext
   * @param nextLink The nextLink from the previous successful call to the ListBuiltInNext method.
   * @param options The options parameters.
   */
  private _listBuiltInNextNext(
    nextLink: string,
    options?: PolicyDefinitionsListBuiltInNextNextOptionalParams
  ): Promise<PolicyDefinitionsListBuiltInNextNextResponse> {
    return this.client.sendOperationRequest(
      { nextLink, options },
      listBuiltInNextNextOperationSpec
    );
  }

  /**
   * ListByManagementGroupNextNext
   * @param managementGroupId The ID of the management group.
   * @param nextLink The nextLink from the previous successful call to the ListByManagementGroupNext
   *                 method.
   * @param options The options parameters.
   */
  private _listByManagementGroupNextNext(
    managementGroupId: string,
    nextLink: string,
    options?: PolicyDefinitionsListByManagementGroupNextNextOptionalParams
  ): Promise<PolicyDefinitionsListByManagementGroupNextNextResponse> {
    return this.client.sendOperationRequest(
      { managementGroupId, nextLink, options },
      listByManagementGroupNextNextOperationSpec
    );
  }
}
// Operation Specifications
const serializer = coreClient.createSerializer(Mappers, /* isXml */ false);

const createOrUpdateOperationSpec: coreClient.OperationSpec = {
  path:
    "/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/policyDefinitions/{policyDefinitionName}",
  httpMethod: "PUT",
  responses: {
    201: {
      bodyMapper: Mappers.PolicyDefinition
    },
    default: {
      bodyMapper: Mappers.CloudError
    }
  },
  requestBody: Parameters.parameters1,
  queryParameters: [Parameters.apiVersion],
  urlParameters: [
    Parameters.$host,
    Parameters.subscriptionId,
    Parameters.policyDefinitionName
  ],
  headerParameters: [Parameters.accept, Parameters.contentType],
  mediaType: "json",
  serializer
};
const deleteOperationSpec: coreClient.OperationSpec = {
  path:
    "/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/policyDefinitions/{policyDefinitionName}",
  httpMethod: "DELETE",
  responses: {
    200: {},
    204: {},
    default: {
      bodyMapper: Mappers.CloudError
    }
  },
  queryParameters: [Parameters.apiVersion],
  urlParameters: [
    Parameters.$host,
    Parameters.subscriptionId,
    Parameters.policyDefinitionName
  ],
  headerParameters: [Parameters.accept],
  serializer
};
const getOperationSpec: coreClient.OperationSpec = {
  path:
    "/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/policyDefinitions/{policyDefinitionName}",
  httpMethod: "GET",
  responses: {
    200: {
      bodyMapper: Mappers.PolicyDefinition
    },
    default: {
      bodyMapper: Mappers.CloudError
    }
  },
  queryParameters: [Parameters.apiVersion],
  urlParameters: [
    Parameters.$host,
    Parameters.subscriptionId,
    Parameters.policyDefinitionName
  ],
  headerParameters: [Parameters.accept],
  serializer
};
const getBuiltInOperationSpec: coreClient.OperationSpec = {
  path:
    "/providers/Microsoft.Authorization/policyDefinitions/{policyDefinitionName}",
  httpMethod: "GET",
  responses: {
    200: {
      bodyMapper: Mappers.PolicyDefinition
    },
    default: {
      bodyMapper: Mappers.CloudError
    }
  },
  queryParameters: [Parameters.apiVersion],
  urlParameters: [Parameters.$host, Parameters.policyDefinitionName],
  headerParameters: [Parameters.accept],
  serializer
};
const createOrUpdateAtManagementGroupOperationSpec: coreClient.OperationSpec = {
  path:
    "/providers/Microsoft.Management/managementGroups/{managementGroupId}/providers/Microsoft.Authorization/policyDefinitions/{policyDefinitionName}",
  httpMethod: "PUT",
  responses: {
    201: {
      bodyMapper: Mappers.PolicyDefinition
    },
    default: {
      bodyMapper: Mappers.CloudError
    }
  },
  requestBody: Parameters.parameters1,
  queryParameters: [Parameters.apiVersion],
  urlParameters: [
    Parameters.$host,
    Parameters.managementGroupId,
    Parameters.policyDefinitionName
  ],
  headerParameters: [Parameters.accept, Parameters.contentType],
  mediaType: "json",
  serializer
};
const deleteAtManagementGroupOperationSpec: coreClient.OperationSpec = {
  path:
    "/providers/Microsoft.Management/managementGroups/{managementGroupId}/providers/Microsoft.Authorization/policyDefinitions/{policyDefinitionName}",
  httpMethod: "DELETE",
  responses: {
    200: {},
    204: {},
    default: {
      bodyMapper: Mappers.CloudError
    }
  },
  queryParameters: [Parameters.apiVersion],
  urlParameters: [
    Parameters.$host,
    Parameters.managementGroupId,
    Parameters.policyDefinitionName
  ],
  headerParameters: [Parameters.accept],
  serializer
};
const getAtManagementGroupOperationSpec: coreClient.OperationSpec = {
  path:
    "/providers/Microsoft.Management/managementGroups/{managementGroupId}/providers/Microsoft.Authorization/policyDefinitions/{policyDefinitionName}",
  httpMethod: "GET",
  responses: {
    200: {
      bodyMapper: Mappers.PolicyDefinition
    },
    default: {
      bodyMapper: Mappers.CloudError
    }
  },
  queryParameters: [Parameters.apiVersion],
  urlParameters: [
    Parameters.$host,
    Parameters.managementGroupId,
    Parameters.policyDefinitionName
  ],
  headerParameters: [Parameters.accept],
  serializer
};
const listOperationSpec: coreClient.OperationSpec = {
  path:
    "/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/policyDefinitions",
  httpMethod: "GET",
  responses: {
    200: {
      bodyMapper: Mappers.PolicyDefinitionListResult
    },
    default: {
      bodyMapper: Mappers.CloudError
    }
  },
  queryParameters: [Parameters.apiVersion, Parameters.filter, Parameters.top],
  urlParameters: [Parameters.$host, Parameters.subscriptionId],
  headerParameters: [Parameters.accept],
  serializer
};
const listBuiltInOperationSpec: coreClient.OperationSpec = {
  path: "/providers/Microsoft.Authorization/policyDefinitions",
  httpMethod: "GET",
  responses: {
    200: {
      bodyMapper: Mappers.PolicyDefinitionListResult
    },
    default: {
      bodyMapper: Mappers.CloudError
    }
  },
  queryParameters: [Parameters.apiVersion, Parameters.filter, Parameters.top],
  urlParameters: [Parameters.$host],
  headerParameters: [Parameters.accept],
  serializer
};
const listByManagementGroupOperationSpec: coreClient.OperationSpec = {
  path:
    "/providers/Microsoft.Management/managementGroups/{managementGroupId}/providers/Microsoft.Authorization/policyDefinitions",
  httpMethod: "GET",
  responses: {
    200: {
      bodyMapper: Mappers.PolicyDefinitionListResult
    },
    default: {
      bodyMapper: Mappers.CloudError
    }
  },
  queryParameters: [Parameters.apiVersion, Parameters.filter, Parameters.top],
  urlParameters: [Parameters.$host, Parameters.managementGroupId],
  headerParameters: [Parameters.accept],
  serializer
};
const listNextOperationSpec: coreClient.OperationSpec = {
  path: "{nextLink}",
  httpMethod: "GET",
  responses: {
    200: {
      bodyMapper: Mappers.PolicyDefinitionListResult
    },
    default: {
      bodyMapper: Mappers.CloudError
    }
  },
  queryParameters: [Parameters.apiVersion, Parameters.filter, Parameters.top],
  urlParameters: [
    Parameters.$host,
    Parameters.nextLink,
    Parameters.subscriptionId
  ],
  headerParameters: [Parameters.accept],
  serializer
};
const listBuiltInNextOperationSpec: coreClient.OperationSpec = {
  path: "{nextLink}",
  httpMethod: "GET",
  responses: {
    200: {
      bodyMapper: Mappers.PolicyDefinitionListResult
    },
    default: {
      bodyMapper: Mappers.CloudError
    }
  },
  queryParameters: [Parameters.apiVersion, Parameters.filter, Parameters.top],
  urlParameters: [Parameters.$host, Parameters.nextLink],
  headerParameters: [Parameters.accept],
  serializer
};
const listByManagementGroupNextOperationSpec: coreClient.OperationSpec = {
  path: "{nextLink}",
  httpMethod: "GET",
  responses: {
    200: {
      bodyMapper: Mappers.PolicyDefinitionListResult
    },
    default: {
      bodyMapper: Mappers.CloudError
    }
  },
  queryParameters: [Parameters.apiVersion, Parameters.filter, Parameters.top],
  urlParameters: [
    Parameters.$host,
    Parameters.nextLink,
    Parameters.managementGroupId
  ],
  headerParameters: [Parameters.accept],
  serializer
};
const listNextNextOperationSpec: coreClient.OperationSpec = {
  path: "{nextLink}",
  httpMethod: "GET",
  responses: {
    200: {
      bodyMapper: Mappers.PolicyDefinitionListResult
    },
    default: {
      bodyMapper: Mappers.CloudError
    }
  },
  queryParameters: [Parameters.apiVersion, Parameters.filter, Parameters.top],
  urlParameters: [
    Parameters.$host,
    Parameters.nextLink,
    Parameters.subscriptionId
  ],
  headerParameters: [Parameters.accept],
  serializer
};
const listBuiltInNextNextOperationSpec: coreClient.OperationSpec = {
  path: "{nextLink}",
  httpMethod: "GET",
  responses: {
    200: {
      bodyMapper: Mappers.PolicyDefinitionListResult
    },
    default: {
      bodyMapper: Mappers.CloudError
    }
  },
  queryParameters: [Parameters.apiVersion, Parameters.filter, Parameters.top],
  urlParameters: [Parameters.$host, Parameters.nextLink],
  headerParameters: [Parameters.accept],
  serializer
};
const listByManagementGroupNextNextOperationSpec: coreClient.OperationSpec = {
  path: "{nextLink}",
  httpMethod: "GET",
  responses: {
    200: {
      bodyMapper: Mappers.PolicyDefinitionListResult
    },
    default: {
      bodyMapper: Mappers.CloudError
    }
  },
  queryParameters: [Parameters.apiVersion, Parameters.filter, Parameters.top],
  urlParameters: [
    Parameters.$host,
    Parameters.nextLink,
    Parameters.managementGroupId
  ],
  headerParameters: [Parameters.accept],
  serializer
};
