let nock = require('nock');

module.exports.hash = "8126d442c16ed9c8bbf329910b4681d5";

module.exports.testInfo = {"uniqueName":{},"newDate":{}}

nock('https://login.microsoftonline.com:443', {"encodedQueryParams":true})
  .post('/azure_tenant_id/oauth2/v2.0/token', "response_type=token&grant_type=client_credentials&client_id=azure_client_id&client_secret=azure_client_secret&scope=https%3A%2F%2Fsanitized%2F")
  .reply(200, {"token_type":"Bearer","expires_in":86399,"ext_expires_in":86399,"access_token":"access_token"}, [
  'Cache-Control',
  'no-store, no-cache',
  'Pragma',
  'no-cache',
  'Content-Type',
  'application/json; charset=utf-8',
  'Expires',
  '-1',
  'Strict-Transport-Security',
  'max-age=31536000; includeSubDomains',
  'X-Content-Type-Options',
  'nosniff',
  'P3P',
  'CP="DSP CUR OTPi IND OTRi ONL FIN"',
  'x-ms-request-id',
  '5ace65de-fb4f-48eb-b58e-daa72e193200',
  'x-ms-ests-server',
  '2.1.11722.21 - SCUS ProdSlices',
  'Set-Cookie',
  'fpc=AhCbJBjHjO9KimZEDsnl1Mq81LWYAgAAAGPXQdgOAAAA; expires=Sat, 26-Jun-2021 18:09:47 GMT; path=/; secure; HttpOnly; SameSite=None',
  'Set-Cookie',
  'x-ms-gateway-slice=estsfd; path=/; secure; samesite=none; httponly',
  'Set-Cookie',
  'stsservicecookie=estsfd; path=/; secure; samesite=none; httponly',
  'Date',
  'Thu, 27 May 2021 18:09:47 GMT',
  'Content-Length',
  '1317'
]);

nock('https://aad_attestation_url.wus.attest.azure.net:443', {"encodedQueryParams":true})
  .post('/attest/Tpm', {"data":"eyJwYXlsb2FkIjp7InR5cGUiOiJhaWtjZXJ0In19"})
  .query(true)
  .reply(400, {"error":{"code":"Bad request","message":"A VBS attestation policy has not been set on the attestation provider."}}, [
  'Connection',
  'close',
  'Date',
  'Thu, 27 May 2021 18:09:47 GMT',
  'Content-Type',
  'application/json; charset=utf-8',
  'Server',
  'Kestrel',
  'Transfer-Encoding',
  'chunked',
  'x-ms-request-id',
  '00-991735db5820154ea4825a45161817af-0000000000000000-00',
  'x-ms-maa-service-version',
  '1.10.01598.0001'
]);
