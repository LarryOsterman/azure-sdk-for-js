import {
  SearchIndexingBufferedSender,
  AzureKeyCredential,
  SearchClient,
  GeographyPoint,
  SearchIndexClient
} from "@azure/search-documents";
import { createIndex, WAIT_TIME } from "../../utils/setup";
import { Hotel } from "../../utils/interfaces";
import { delay } from "@azure/core-http";

/**
 * This sample is to demonstrate the use of SearchIndexingBufferedSender.
 * In this sample, the autoFlush is set to false. i.e. the user
 * wants to call the flush manually.
 */
const endpoint = process.env.SEARCH_API_ENDPOINT || "";
const apiKey = process.env.SEARCH_API_KEY || "";
const TEST_INDEX_NAME = "hotel-live-sample-test1";

export async function main() {
  console.log(`Running SearchIndexingBufferedSender-uploadDocuments-Without AutoFlush Sample`);

  const credential = new AzureKeyCredential(apiKey);
  const searchClient: SearchClient<Hotel> = new SearchClient<Hotel>(
    endpoint,
    TEST_INDEX_NAME,
    credential
  );
  const indexClient: SearchIndexClient = new SearchIndexClient(endpoint, credential);

  await createIndex(indexClient, TEST_INDEX_NAME);
  await delay(WAIT_TIME);

  const bufferedClient: SearchIndexingBufferedSender<Hotel> = searchClient.getSearchIndexingBufferedSenderInstance(
    {
      autoFlush: false
    }
  );

  bufferedClient.on("batchAdded", (response: any) => {
    console.log("Batch Added Event has been receieved....");
  });

  bufferedClient.on("beforeDocumentSent", (response: any) => {
    console.log("Before Document Sent Event has been receieved....");
  });

  bufferedClient.on("batchSucceeded", (response: any) => {
    console.log("Batch Succeeded Event has been receieved....");
    console.log(response);
  });

  bufferedClient.on("batchFailed", (response: any) => {
    console.log("Batch Failed Event has been receieved....");
    console.log(response);
  });

  bufferedClient.uploadDocuments([
    {
      hotelId: "1",
      description:
        "Best hotel in town if you like luxury hotels. They have an amazing infinity pool, a spa, " +
        "and a really helpful concierge. The location is perfect -- right downtown, close to all " +
        "the tourist attractions. We highly recommend this hotel.",
      descriptionFr:
        "Meilleur hôtel en ville si vous aimez les hôtels de luxe. Ils ont une magnifique piscine " +
        "à débordement, un spa et un concierge très utile. L'emplacement est parfait – en plein " +
        "centre, à proximité de toutes les attractions touristiques. Nous recommandons fortement " +
        "cet hôtel.",
      hotelName: "Fancy Stay",
      category: "Luxury",
      tags: ["pool", "view", "wifi", "concierge"],
      parkingIncluded: false,
      lastRenovationDate: new Date(2010, 5, 27),
      rating: 5,
      location: new GeographyPoint(47.678581, -122.131577)
    }
  ]);

  await bufferedClient.flush();
  bufferedClient.dispose();
  await indexClient.deleteIndex(TEST_INDEX_NAME);
  await delay(WAIT_TIME);
}

main();