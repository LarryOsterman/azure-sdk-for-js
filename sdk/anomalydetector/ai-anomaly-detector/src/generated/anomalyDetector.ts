/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License.
 *
 * Code generated by Microsoft (R) AutoRest Code Generator.
 * Changes may cause incorrect behavior and will be lost if the code is regenerated.
 */

import * as coreHttp from "@azure/core-http";
import "@azure/core-paging";
import { PagedAsyncIterableIterator } from "@azure/core-paging";
import { SpanStatusCode } from "@azure/core-tracing";
import { createSpan } from "./tracing";
import * as Parameters from "./models/parameters";
import * as Mappers from "./models/mappers";
import { AnomalyDetectorContext } from "./anomalyDetectorContext";
import {
  AnomalyDetectorOptionalParams,
  ModelSnapshot,
  AnomalyDetectorListMultivariateModelNextOptionalParams,
  AnomalyDetectorListMultivariateModelOptionalParams,
  DetectRequest,
  AnomalyDetectorDetectEntireSeriesResponse,
  AnomalyDetectorDetectLastPointResponse,
  DetectChangePointRequest,
  AnomalyDetectorDetectChangePointResponse,
  ModelInfo,
  AnomalyDetectorTrainMultivariateModelResponse,
  AnomalyDetectorGetMultivariateModelResponse,
  DetectionRequest,
  AnomalyDetectorDetectAnomalyResponse,
  AnomalyDetectorGetDetectionResultResponse,
  AnomalyDetectorExportModelResponse,
  AnomalyDetectorListMultivariateModelResponse,
  AnomalyDetectorListMultivariateModelNextResponse
} from "./models";

/// <reference lib="esnext.asynciterable" />
/** @hidden */
export class AnomalyDetector extends AnomalyDetectorContext {
  /**
   * Initializes a new instance of the AnomalyDetector class.
   * @param endpoint Supported Cognitive Services endpoints (protocol and hostname, for example:
   *                 https://westus2.api.cognitive.microsoft.com).
   * @param options The parameter options
   */
  constructor(endpoint: string, options?: AnomalyDetectorOptionalParams) {
    super(endpoint, options);
  }

  /**
   * List models of a subscription
   * @param options The options parameters.
   */
  public listMultivariateModel(
    options?: AnomalyDetectorListMultivariateModelOptionalParams
  ): PagedAsyncIterableIterator<ModelSnapshot> {
    const iter = this.listMultivariateModelPagingAll(options);
    return {
      next() {
        return iter.next();
      },
      [Symbol.asyncIterator]() {
        return this;
      },
      byPage: () => {
        return this.listMultivariateModelPagingPage(options);
      }
    };
  }

  private async *listMultivariateModelPagingPage(
    options?: AnomalyDetectorListMultivariateModelOptionalParams
  ): AsyncIterableIterator<ModelSnapshot[]> {
    let result = await this._listMultivariateModel(options);
    yield result.models || [];
    let continuationToken = result.nextLink;
    while (continuationToken) {
      result = await this._listMultivariateModelNext(continuationToken, options);
      continuationToken = result.nextLink;
      yield result.models || [];
    }
  }

  private async *listMultivariateModelPagingAll(
    options?: AnomalyDetectorListMultivariateModelOptionalParams
  ): AsyncIterableIterator<ModelSnapshot> {
    for await (const page of this.listMultivariateModelPagingPage(options)) {
      yield* page;
    }
  }

  /**
   * This operation generates a model with an entire series, each point is detected with the same model.
   * With this method, points before and after a certain point are used to determine whether it is an
   * anomaly. The entire detection can give user an overall status of the time series.
   * @param body Time series points and period if needed. Advanced model parameters can also be set in
   *             the request.
   * @param options The options parameters.
   */
  async detectEntireSeries(
    body: DetectRequest,
    options?: coreHttp.OperationOptions
  ): Promise<AnomalyDetectorDetectEntireSeriesResponse> {
    const { span, updatedOptions } = createSpan(
      "AnomalyDetector-detectEntireSeries",
      options || {}
    );
    const operationArguments: coreHttp.OperationArguments = {
      body,
      options: coreHttp.operationOptionsToRequestOptionsBase(updatedOptions || {})
    };
    try {
      const result = await this.sendOperationRequest(
        operationArguments,
        detectEntireSeriesOperationSpec
      );
      return result as AnomalyDetectorDetectEntireSeriesResponse;
    } catch (error) {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: error.message
      });
      throw error;
    } finally {
      span.end();
    }
  }

  /**
   * This operation generates a model using points before the latest one. With this method, only
   * historical points are used to determine whether the target point is an anomaly. The latest point
   * detecting operation matches the scenario of real-time monitoring of business metrics.
   * @param body Time series points and period if needed. Advanced model parameters can also be set in
   *             the request.
   * @param options The options parameters.
   */
  async detectLastPoint(
    body: DetectRequest,
    options?: coreHttp.OperationOptions
  ): Promise<AnomalyDetectorDetectLastPointResponse> {
    const { span, updatedOptions } = createSpan("AnomalyDetector-detectLastPoint", options || {});
    const operationArguments: coreHttp.OperationArguments = {
      body,
      options: coreHttp.operationOptionsToRequestOptionsBase(updatedOptions || {})
    };
    try {
      const result = await this.sendOperationRequest(
        operationArguments,
        detectLastPointOperationSpec
      );
      return result as AnomalyDetectorDetectLastPointResponse;
    } catch (error) {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: error.message
      });
      throw error;
    } finally {
      span.end();
    }
  }

  /**
   * Evaluate change point score of every series point
   * @param body Time series points and granularity is needed. Advanced model parameters can also be set
   *             in the request if needed.
   * @param options The options parameters.
   */
  async detectChangePoint(
    body: DetectChangePointRequest,
    options?: coreHttp.OperationOptions
  ): Promise<AnomalyDetectorDetectChangePointResponse> {
    const { span, updatedOptions } = createSpan("AnomalyDetector-detectChangePoint", options || {});
    const operationArguments: coreHttp.OperationArguments = {
      body,
      options: coreHttp.operationOptionsToRequestOptionsBase(updatedOptions || {})
    };
    try {
      const result = await this.sendOperationRequest(
        operationArguments,
        detectChangePointOperationSpec
      );
      return result as AnomalyDetectorDetectChangePointResponse;
    } catch (error) {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: error.message
      });
      throw error;
    } finally {
      span.end();
    }
  }

  /**
   * Create and train a multivariate anomaly detection model. The request must include a source parameter
   * to indicate an externally accessible Azure storage Uri (preferably a Shared Access Signature Uri).
   * All time-series used in generate the model must be zipped into one single file. Each time-series
   * will be in a single CSV file in which the first column is timestamp and the second column is value.
   * @param modelRequest Training request
   * @param options The options parameters.
   */
  async trainMultivariateModel(
    modelRequest: ModelInfo,
    options?: coreHttp.OperationOptions
  ): Promise<AnomalyDetectorTrainMultivariateModelResponse> {
    const { span, updatedOptions } = createSpan(
      "AnomalyDetector-trainMultivariateModel",
      options || {}
    );
    const operationArguments: coreHttp.OperationArguments = {
      modelRequest,
      options: coreHttp.operationOptionsToRequestOptionsBase(updatedOptions || {})
    };
    try {
      const result = await this.sendOperationRequest(
        operationArguments,
        trainMultivariateModelOperationSpec
      );
      return result as AnomalyDetectorTrainMultivariateModelResponse;
    } catch (error) {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: error.message
      });
      throw error;
    } finally {
      span.end();
    }
  }

  /**
   * Get detailed information of multivariate model, including the training status and variables used in
   * the model.
   * @param modelId Model identifier.
   * @param options The options parameters.
   */
  async getMultivariateModel(
    modelId: string,
    options?: coreHttp.OperationOptions
  ): Promise<AnomalyDetectorGetMultivariateModelResponse> {
    const { span, updatedOptions } = createSpan(
      "AnomalyDetector-getMultivariateModel",
      options || {}
    );
    const operationArguments: coreHttp.OperationArguments = {
      modelId,
      options: coreHttp.operationOptionsToRequestOptionsBase(updatedOptions || {})
    };
    try {
      const result = await this.sendOperationRequest(
        operationArguments,
        getMultivariateModelOperationSpec
      );
      return result as AnomalyDetectorGetMultivariateModelResponse;
    } catch (error) {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: error.message
      });
      throw error;
    } finally {
      span.end();
    }
  }

  /**
   * Delete an existing multivariate model according to the modelId
   * @param modelId Model identifier.
   * @param options The options parameters.
   */
  async deleteMultivariateModel(
    modelId: string,
    options?: coreHttp.OperationOptions
  ): Promise<coreHttp.RestResponse> {
    const { span, updatedOptions } = createSpan(
      "AnomalyDetector-deleteMultivariateModel",
      options || {}
    );
    const operationArguments: coreHttp.OperationArguments = {
      modelId,
      options: coreHttp.operationOptionsToRequestOptionsBase(updatedOptions || {})
    };
    try {
      const result = await this.sendOperationRequest(
        operationArguments,
        deleteMultivariateModelOperationSpec
      );
      return result as coreHttp.RestResponse;
    } catch (error) {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: error.message
      });
      throw error;
    } finally {
      span.end();
    }
  }

  /**
   * Submit detection multivariate anomaly task with the trained model of modelId, the input schema
   * should be the same with the training request. Thus request will be complete asynchronously and will
   * return a resultId for querying the detection result.The request should be a source link to indicate
   * an externally accessible Azure storage Uri (preferably a Shared Access Signature Uri). All
   * time-series used in generate the model must be zipped into one single file. Each time-series will be
   * as follows: the first column is timestamp and the second column is value.
   * @param modelId Model identifier.
   * @param detectionRequest Detect anomaly request
   * @param options The options parameters.
   */
  async detectAnomaly(
    modelId: string,
    detectionRequest: DetectionRequest,
    options?: coreHttp.OperationOptions
  ): Promise<AnomalyDetectorDetectAnomalyResponse> {
    const { span, updatedOptions } = createSpan("AnomalyDetector-detectAnomaly", options || {});
    const operationArguments: coreHttp.OperationArguments = {
      modelId,
      detectionRequest,
      options: coreHttp.operationOptionsToRequestOptionsBase(updatedOptions || {})
    };
    try {
      const result = await this.sendOperationRequest(
        operationArguments,
        detectAnomalyOperationSpec
      );
      return result as AnomalyDetectorDetectAnomalyResponse;
    } catch (error) {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: error.message
      });
      throw error;
    } finally {
      span.end();
    }
  }

  /**
   * Get multivariate anomaly detection result based on resultId returned by the DetectAnomalyAsync api
   * @param resultId Result identifier.
   * @param options The options parameters.
   */
  async getDetectionResult(
    resultId: string,
    options?: coreHttp.OperationOptions
  ): Promise<AnomalyDetectorGetDetectionResultResponse> {
    const { span, updatedOptions } = createSpan(
      "AnomalyDetector-getDetectionResult",
      options || {}
    );
    const operationArguments: coreHttp.OperationArguments = {
      resultId,
      options: coreHttp.operationOptionsToRequestOptionsBase(updatedOptions || {})
    };
    try {
      const result = await this.sendOperationRequest(
        operationArguments,
        getDetectionResultOperationSpec
      );
      return result as AnomalyDetectorGetDetectionResultResponse;
    } catch (error) {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: error.message
      });
      throw error;
    } finally {
      span.end();
    }
  }

  /**
   * Export multivariate anomaly detection model based on modelId
   * @param modelId Model identifier.
   * @param options The options parameters.
   */
  async exportModel(
    modelId: string,
    options?: coreHttp.OperationOptions
  ): Promise<AnomalyDetectorExportModelResponse> {
    const { span, updatedOptions } = createSpan("AnomalyDetector-exportModel", options || {});
    const operationArguments: coreHttp.OperationArguments = {
      modelId,
      options: coreHttp.operationOptionsToRequestOptionsBase(updatedOptions || {})
    };
    try {
      const result = await this.sendOperationRequest(operationArguments, exportModelOperationSpec);
      return result as AnomalyDetectorExportModelResponse;
    } catch (error) {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: error.message
      });
      throw error;
    } finally {
      span.end();
    }
  }

  /**
   * List models of a subscription
   * @param options The options parameters.
   */
  private async _listMultivariateModel(
    options?: AnomalyDetectorListMultivariateModelOptionalParams
  ): Promise<AnomalyDetectorListMultivariateModelResponse> {
    const { span, updatedOptions } = createSpan(
      "AnomalyDetector-_listMultivariateModel",
      options || {}
    );
    const operationArguments: coreHttp.OperationArguments = {
      options: coreHttp.operationOptionsToRequestOptionsBase(updatedOptions || {})
    };
    try {
      const result = await this.sendOperationRequest(
        operationArguments,
        listMultivariateModelOperationSpec
      );
      return result as AnomalyDetectorListMultivariateModelResponse;
    } catch (error) {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: error.message
      });
      throw error;
    } finally {
      span.end();
    }
  }

  /**
   * ListMultivariateModelNext
   * @param nextLink The nextLink from the previous successful call to the ListMultivariateModel method.
   * @param options The options parameters.
   */
  private async _listMultivariateModelNext(
    nextLink: string,
    options?: AnomalyDetectorListMultivariateModelNextOptionalParams
  ): Promise<AnomalyDetectorListMultivariateModelNextResponse> {
    const { span, updatedOptions } = createSpan(
      "AnomalyDetector-_listMultivariateModelNext",
      options || {}
    );
    const operationArguments: coreHttp.OperationArguments = {
      nextLink,
      options: coreHttp.operationOptionsToRequestOptionsBase(updatedOptions || {})
    };
    try {
      const result = await this.sendOperationRequest(
        operationArguments,
        listMultivariateModelNextOperationSpec
      );
      return result as AnomalyDetectorListMultivariateModelNextResponse;
    } catch (error) {
      span.setStatus({
        code: SpanStatusCode.ERROR,
        message: error.message
      });
      throw error;
    } finally {
      span.end();
    }
  }
}
// Operation Specifications
const serializer = new coreHttp.Serializer(Mappers, /* isXml */ false);

const detectEntireSeriesOperationSpec: coreHttp.OperationSpec = {
  path: "/timeseries/entire/detect",
  httpMethod: "POST",
  responses: {
    200: {
      bodyMapper: Mappers.DetectEntireResponse
    },
    default: {
      bodyMapper: Mappers.AnomalyDetectorError
    }
  },
  requestBody: Parameters.body,
  urlParameters: [Parameters.endpoint],
  headerParameters: [Parameters.contentType, Parameters.accept],
  mediaType: "json",
  serializer
};
const detectLastPointOperationSpec: coreHttp.OperationSpec = {
  path: "/timeseries/last/detect",
  httpMethod: "POST",
  responses: {
    200: {
      bodyMapper: Mappers.DetectLastPointResponse
    },
    default: {
      bodyMapper: Mappers.AnomalyDetectorError
    }
  },
  requestBody: Parameters.body,
  urlParameters: [Parameters.endpoint],
  headerParameters: [Parameters.contentType, Parameters.accept],
  mediaType: "json",
  serializer
};
const detectChangePointOperationSpec: coreHttp.OperationSpec = {
  path: "/timeseries/changepoint/detect",
  httpMethod: "POST",
  responses: {
    200: {
      bodyMapper: Mappers.DetectChangePointResponse
    },
    default: {
      bodyMapper: Mappers.AnomalyDetectorError
    }
  },
  requestBody: Parameters.body1,
  urlParameters: [Parameters.endpoint],
  headerParameters: [Parameters.contentType, Parameters.accept],
  mediaType: "json",
  serializer
};
const trainMultivariateModelOperationSpec: coreHttp.OperationSpec = {
  path: "/multivariate/models",
  httpMethod: "POST",
  responses: {
    201: {
      headersMapper: Mappers.AnomalyDetectorTrainMultivariateModelHeaders
    },
    default: {
      bodyMapper: Mappers.ErrorResponse
    }
  },
  requestBody: Parameters.modelRequest,
  urlParameters: [Parameters.endpoint],
  headerParameters: [Parameters.contentType, Parameters.accept],
  mediaType: "json",
  serializer
};
const getMultivariateModelOperationSpec: coreHttp.OperationSpec = {
  path: "/multivariate/models/{modelId}",
  httpMethod: "GET",
  responses: {
    200: {
      bodyMapper: Mappers.Model
    },
    default: {
      bodyMapper: Mappers.ErrorResponse
    }
  },
  urlParameters: [Parameters.endpoint, Parameters.modelId],
  headerParameters: [Parameters.accept],
  serializer
};
const deleteMultivariateModelOperationSpec: coreHttp.OperationSpec = {
  path: "/multivariate/models/{modelId}",
  httpMethod: "DELETE",
  responses: {
    204: {},
    default: {
      bodyMapper: Mappers.ErrorResponse
    }
  },
  urlParameters: [Parameters.endpoint, Parameters.modelId],
  headerParameters: [Parameters.accept],
  serializer
};
const detectAnomalyOperationSpec: coreHttp.OperationSpec = {
  path: "/multivariate/models/{modelId}/detect",
  httpMethod: "POST",
  responses: {
    201: {
      headersMapper: Mappers.AnomalyDetectorDetectAnomalyHeaders
    },
    default: {
      bodyMapper: Mappers.ErrorResponse
    }
  },
  requestBody: Parameters.detectionRequest,
  urlParameters: [Parameters.endpoint, Parameters.modelId],
  headerParameters: [Parameters.contentType, Parameters.accept],
  mediaType: "json",
  serializer
};
const getDetectionResultOperationSpec: coreHttp.OperationSpec = {
  path: "/multivariate/results/{resultId}",
  httpMethod: "GET",
  responses: {
    200: {
      bodyMapper: Mappers.DetectionResult
    },
    default: {
      bodyMapper: Mappers.ErrorResponse
    }
  },
  urlParameters: [Parameters.endpoint, Parameters.resultId],
  headerParameters: [Parameters.accept],
  serializer
};
const exportModelOperationSpec: coreHttp.OperationSpec = {
  path: "/multivariate/models/{modelId}/export",
  httpMethod: "GET",
  responses: {
    200: {
      bodyMapper: {
        type: { name: "Stream" },
        serializedName: "parsedResponse"
      },
      headersMapper: Mappers.AnomalyDetectorExportModelHeaders
    },
    default: {}
  },
  urlParameters: [Parameters.endpoint, Parameters.modelId],
  headerParameters: [Parameters.accept1],
  serializer
};
const listMultivariateModelOperationSpec: coreHttp.OperationSpec = {
  path: "/multivariate/models",
  httpMethod: "GET",
  responses: {
    200: {
      bodyMapper: Mappers.ModelList
    },
    default: {
      bodyMapper: Mappers.ErrorResponse
    }
  },
  queryParameters: [Parameters.skip, Parameters.top],
  urlParameters: [Parameters.endpoint],
  headerParameters: [Parameters.accept],
  serializer
};
const listMultivariateModelNextOperationSpec: coreHttp.OperationSpec = {
  path: "{nextLink}",
  httpMethod: "GET",
  responses: {
    200: {
      bodyMapper: Mappers.ModelList
    },
    default: {
      bodyMapper: Mappers.ErrorResponse
    }
  },
  queryParameters: [Parameters.skip, Parameters.top],
  urlParameters: [Parameters.endpoint, Parameters.nextLink],
  headerParameters: [Parameters.accept],
  serializer
};