    /*
     * Licensed under the Apache License, Version 2.0 (the "License");
     * you may not use this file except in compliance with the License.
     * You may obtain a copy of the License at
     *
     *     http://www.apache.org/licenses/LICENSE-2.0
     *
     * Unless required by applicable law or agreed to in writing, software
     * distributed under the License is distributed on an "AS IS" BASIS,
     * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
     * See the License for the specific language governing permissions and
     * limitations under the License.
     */

    package io.tokenchannel;

    import com.google.gson.Gson;
    import io.tokenchannel.exceptions.*;

    import java.io.IOException;
    import java.io.UnsupportedEncodingException;
    import java.net.HttpURLConnection;
    import java.net.URI;
    import java.net.URLEncoder;
    import java.net.http.HttpClient;
    import java.net.http.HttpRequest;
    import java.net.http.HttpResponse;
    import java.nio.charset.StandardCharsets;
    import java.time.Duration;
    import java.util.Arrays;
    import java.util.List;
    import java.util.concurrent.CompletableFuture;

    public class TokenChannel {

        public static final String TOKENCHANNEL_BASE_URI = "https://api.tokenchannel.io";
        private final HttpClient client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .build();
        private final TokenChannelProperties properties;
        private final Gson gson;

        public TokenChannel(TokenChannelProperties properties, Gson gson) {
            this.properties = properties;
            this.gson = gson;
        }

        /**
         * Creates a challenge, ie, generates a token to be sent by a given a channel to a given identifier
         *
         * @param channel    - The channel the token is being delivered
         * @param identifier - the customer identifier in the given channel
         * @param options    - The challenge workflow configuration
         * @throws InvalidIdentifierException whether the identifier is invalid for the given channel
         * @throws TargetOptOutException      whether the target user opted out this service via this channel
         * @throws BadRequestException        whether there is an invalid value in the request. The field errorInfo in the BadRequestError describes the invalid value
         * @throws OutOfBalanceException      whether there is not enough balance to attend a balance consumer challenge creation
         * @throws ForbiddenException         whether requesting an action that provided api key is not allowed
         * @throws UnauthorizedException      whether an invalid api key value is provided
         * @throws QuotaExceededException     whether Sandbox quota, QPS o QPM have been exceeded
         */
        public CompletableFuture<ChallengeResponse> challenge(ChannelType channel, String identifier, ChallengeOptions options) {

            if (this.properties.getTestMode() != null && this.properties.getTestMode()) {
                options.setTest(true);
            }

            try {
                final HttpRequest httpRequest =
                        this.buildDefaultHttpRequest(URI.create(String.format("%s/challenge/%s/%s", TOKENCHANNEL_BASE_URI,
                                channel.toString(), URLEncoder.encode(identifier, StandardCharsets.UTF_8.toString()))))
                                .header("Content-Type", "application/json")
                                .POST(HttpRequest.BodyPublishers.ofString(options != null ? gson.toJson(options) : "{}"))
                                .build();
                CompletableFuture<HttpResponse<String>> response = client.sendAsync(httpRequest, HttpResponse.BodyHandlers.ofString());
                return response.thenApply(r -> this.processResponse(r, ChallengeResponse.class));
            } catch (UnsupportedEncodingException ie) {
                throw new TokenChannelException(ie);
            }
        }

        /**
         * Verifies a previously created challenge
         *
         * @param requestId - The handle to a given challenge
         * @param authCode  - The token or validation code to try challenge authentication
         * @throws InvalidCodeException         whether the token or validation code provide is invalid
         * @throws BadRequestException          whether the requestId format is invalid
         * @throws ChallengeClosedException     whether the challenge is closed and no interaction is expected
         * @throws ChallengeExpiredException    whether the challenge validity is over
         * @throws ChallengeNotFoundException   whether the requestId is well formatted but a challenge for that id cannot be found
         * @throws MaxAttemptsExceededException whether the max number ot attempts allowed has been reached
         * @throws ForbiddenException           whether requesting an action that provided api key is not allowed to perform
         * @throws UnauthorizedException        whether an invalid api key value is provided
         * @throws QuotaExceededException       whether Sandbox quota, QPS o QPM have been exceeded
         */
        public CompletableFuture<AuthenticateResponse> authenticate(String requestId, String authCode) {

            final HttpRequest httpRequest =
                    this.buildDefaultHttpRequest(URI.create(String.format("%s/authenticate/%s/%s", TOKENCHANNEL_BASE_URI,
                            requestId, authCode)))
                            .POST(HttpRequest.BodyPublishers.ofString("{}"))
                            .build();

            CompletableFuture<HttpResponse<String>> response = client.sendAsync(httpRequest, HttpResponse.BodyHandlers.ofString());
            return response.thenApply(r -> this.processResponse(r, AuthenticateResponse.class));
        }


        /**
         * Retrieves the validation code of a challenge that was previously created with test mode enabled
         *
         * @param requestId - The handle to a given challenge
         * @throws BadRequestException    whether the requestId format is invalid
         * @throws ForbiddenException     whether requesting an action that provided api key is not allowed to perform
         * @throws UnauthorizedException  whether an invalid api key value is provided
         * @throws QuotaExceededException whether QPS o QPM have been exceeded
         */
        public CompletableFuture<TestResponse> getValidationCodeByTestChallengeId(String requestId) {

            final HttpRequest httpRequest =
                    this.buildDefaultHttpRequest(URI.create(String.format("%s/test/%s", TOKENCHANNEL_BASE_URI, requestId)))
                            .GET()
                            .build();

            CompletableFuture<HttpResponse<String>> response = client.sendAsync(httpRequest, HttpResponse.BodyHandlers.ofString());
            return response.thenApply(r -> this.processResponse(r, TestResponse.class));
        }

        /**
         * Retrieves the countries TokenChannel service is available
         *
         * @throws QuotaExceededException whether QPS o QPM have been exceeded
         */
        public CompletableFuture<List<String>> getSupportedCountries() {

            final HttpRequest httpRequest =
                    this.buildDefaultHttpRequest(URI.create(String.format("%s/countries", TOKENCHANNEL_BASE_URI)))
                            .GET().build();

            CompletableFuture<HttpResponse<String>> response = client.sendAsync(httpRequest, HttpResponse.BodyHandlers.ofString());
            return response.thenApply(r -> Arrays.asList(this.processResponse(r, String[].class)));
        }

        /**
         * Retrieves the available languages or locales for the token notification templates
         *
         * @throws QuotaExceededException whether QPS o QPM have been exceeded
         */
        public CompletableFuture<List<String>> getSupportedLanguages() {
            final HttpRequest httpRequest =
                    this.buildDefaultHttpRequest(URI.create(String.format("%s/languages", TOKENCHANNEL_BASE_URI)))
                            .GET().build();
            CompletableFuture<HttpResponse<String>> response = client.sendAsync(httpRequest, HttpResponse.BodyHandlers.ofString());
            return response.thenApply(r -> Arrays.asList(this.processResponse(r, String[].class)));
        }

        /**
         * Retrieves the SMS pricing list for supported countries
         *
         * @throws QuotaExceededException whether QPS o QPM have been exceeded
         */
        public CompletableFuture<List<SMSPriceItem>> getSMSPrices() {

            final HttpRequest httpRequest =
                    this.buildDefaultHttpRequest(URI.create(String.format("%s/pricing/sms", TOKENCHANNEL_BASE_URI)))
                            .GET().build();
            CompletableFuture<HttpResponse<String>> response = client.sendAsync(httpRequest, HttpResponse.BodyHandlers.ofString());
            return response.thenApply(r -> Arrays.asList(this.processResponse(r, SMSPriceItem[].class)));
        }

        /**
         * Retrieves the voice call pricing list for supported countries
         *
         * @throws QuotaExceededException whether QPS o QPM have been exceeded
         */
        public CompletableFuture<List<VoicePriceItem>> getVoicePrices() {

            final HttpRequest httpRequest =
                    this.buildDefaultHttpRequest(URI.create(String.format("%s/pricing/voice", TOKENCHANNEL_BASE_URI)))
                            .GET().build();
            CompletableFuture<HttpResponse<String>> response = client.sendAsync(httpRequest, HttpResponse.BodyHandlers.ofString());
            return response.thenApply(r -> Arrays.asList(this.processResponse(r, VoicePriceItem[].class)));
        }

        private HttpRequest.Builder buildDefaultHttpRequest(URI uri) {
            return HttpRequest.newBuilder()
                    .timeout(Duration.ofSeconds(30L))
                    .header("X-Api-Key", this.properties.getApiKey())
                    .header("User-Agent", "TokenChannel/Java11")
                    .header("Accept", "application/json; utf-8")
                    .uri(uri);
        }

        private <T> T processResponse(HttpResponse<String> response, Class<T> responseType) {
            if (response.statusCode() == 200) {
                return gson.fromJson(response.body(), responseType);
            } else if (response.statusCode() == 400 ||
                    response.statusCode() == 404) {
                ErrorInfo errorInfo = gson.fromJson(response.body(), ErrorInfo.class);
                if (response.statusCode() == 400) {
                    if (errorInfo.getCode().equals("InvalidCode")) {
                        throw new InvalidCodeException();
                    } else if (errorInfo.getCode().equals("InvalidIdentifier")) {
                        throw new InvalidIdentifierException(errorInfo.getMessage());
                    } else if (errorInfo.getCode().equals("OptOut")) {
                        throw new TargetOptOutException();
                    }
                    throw new BadRequestException(errorInfo);
                } else { // 404
                    if (errorInfo.getCode().equals("ChallengeExpired")) {
                        throw new ChallengeExpiredException();
                    } else if (errorInfo.getCode().equals("ChallengeClosed")) {
                        throw new ChallengeClosedException();
                    } else if (errorInfo.getCode().equals("MaxAttemptsExceeded")) {
                        throw new MaxAttemptsExceededException();
                    }
                    throw new ChallengeNotFoundException();
                }
            } else if (response.statusCode() == 401) {
                throw new UnauthorizedException();
            } else if (response.statusCode() == 402) {
                throw new OutOfBalanceException();
            } else if (response.statusCode() == 403) {
                throw new ForbiddenException();
            } else if (response.statusCode() == 429) {
                throw new QuotaExceededException();
            }
            throw new TokenChannelException(String.format("Unexpected error response"));
        }

    }
