/** **************************************************************************
 * request.c
 * 
 * Copyright 2008 Bryan Ischo <bryan@ischo.com>
 * 
 * This file is part of libs3.
 * 
 * libs3 is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, version 3 of the License.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of this library and its programs with the
 * OpenSSL library, and distribute linked combinations including the two.
 *
 * libs3 is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License version 3
 * along with libs3, in a file named COPYING.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 ************************************************************************** **/

#include <ctype.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include "request.h"
#include "request_context.h"
#include "response_headers_handler.h"
#include "util.h"

#include "sha256.h"

//#define MY_DEBUG
//#define MY_DEBUG_ALL

#define USER_AGENT_SIZE 256
#define REQUEST_STACK_SIZE 32

static char userAgentG[USER_AGENT_SIZE];

static pthread_mutex_t requestStackMutexG;

static Request *requestStackG[REQUEST_STACK_SIZE];

static int requestStackCountG;

char defaultHostNameG[S3_MAX_HOSTNAME_SIZE];


typedef struct RequestComputedValues
{
	time_t now;

	char payload_hexhash[64 + 1];

    // All x-amz- headers, in normalized form (i.e. NAME: VALUE, no other ws)
    char *amzHeaders[S3_MAX_METADATA_COUNT + 2]; // + 2 for acl and date

    // The number of x-amz- headers
    int amzHeadersCount;

    // Storage for amzHeaders (the +256 is for x-amz-acl and x-amz-date)
    char amzHeadersRaw[COMPACTED_METADATA_BUFFER_SIZE + 256 + 1];

    // Canonicalized x-amz- headers
    string_multibuffer(canonicalizedAmzHeaders,
                       COMPACTED_METADATA_BUFFER_SIZE + 256 + 1);

// 	// Canonicalized x-amz- headers(only name)
// 	string_multibuffer(canonicalizedAmzHeadersNameOnly,
// 		COMPACTED_METADATA_BUFFER_SIZE + 256 + 1 - 64);

// 	// The number of x-amz- headers
// 	int stdHeadersCount;
// 
// 	// Storage for amzHeaders (the +256 is for x-amz-acl and x-amz-date)
// 	char stdHeadersRaw[COMPACTED_METADATA_BUFFER_SIZE + 256 + 1];


    // URL-Encoded key
    char urlEncodedKey[MAX_URLENCODED_KEY_SIZE + 1];

    // Canonicalized resource
    char canonicalizedResource[MAX_CANONICALIZED_RESOURCE_SIZE + 1];

    // Cache-Control header (or empty)
    char cacheControlHeader[128];

    // Content-Type header (or empty)
    char contentTypeHeader[128];

    // Content-MD5 header (or empty)
    char md5Header[128];

    // Content-Disposition header (or empty)
    char contentDispositionHeader[128];

    // Content-Encoding header (or empty)
    char contentEncodingHeader[128];

    // Expires header (or empty)
    char expiresHeader[128];

    // If-Modified-Since header
    char ifModifiedSinceHeader[128];

    // If-Unmodified-Since header
    char ifUnmodifiedSinceHeader[128];

    // If-Match header
    char ifMatchHeader[128];

    // If-None-Match header
    char ifNoneMatchHeader[128];

    // Range header
    char rangeHeader[128];

    // Authorization header
    char authorizationHeader[512];
} RequestComputedValues;


// Called whenever we detect that the request headers have been completely
// processed; which happens either when we get our first read/write callback,
// or the request is finished being procesed.  Returns nonzero on success,
// zero on failure.
static void request_headers_done(Request *request)
{
    if (request->propertiesCallbackMade) {
        return;
    }

    request->propertiesCallbackMade = 1;

    // Get the http response code
    long httpResponseCode;
    request->httpResponseCode = 0;
    if (curl_easy_getinfo(request->curl, CURLINFO_RESPONSE_CODE, 
                          &httpResponseCode) != CURLE_OK) {
        // Not able to get the HTTP response code - error
        request->status = S3StatusInternalError;
        return;
    }
    else {
        request->httpResponseCode = httpResponseCode;
    }

    response_headers_handler_done(&(request->responseHeadersHandler), 
                                  request->curl);

    // Only make the callback if it was a successful request; otherwise we're
    // returning information about the error response itself
    if (request->propertiesCallback &&
        (request->httpResponseCode >= 200) &&
        (request->httpResponseCode <= 299)) {
        request->status = (*(request->propertiesCallback))
            (&(request->responseHeadersHandler.responseProperties), 
             request->callbackData);
    }
}


static size_t curl_header_func(void *ptr, size_t size, size_t nmemb,
                               void *data)
{
    Request *request = (Request *) data;

    int len = size * nmemb;

    response_headers_handler_add
        (&(request->responseHeadersHandler), (char *) ptr, len);

    return len;
}


static size_t curl_read_func(void *ptr, size_t size, size_t nmemb, void *data)
{
    Request *request = (Request *) data;

    int len = size * nmemb;

    // CURL may call this function before response headers are available,
    // so don't assume response headers are available and attempt to parse
    // them.  Leave that to curl_write_func, which is guaranteed to be called
    // only after headers are available.

    if (request->status != S3StatusOK) {
        return CURL_READFUNC_ABORT;
    }

#ifdef MY_DEBUG
	printf("curl_read_func size = %d, nmemb = %d\n", (int)size, (int)nmemb);
#endif //MY _DEBUG

    // If there is no data callback, or the data callback has already returned
    // contentLength bytes, return 0;
    if (!request->toS3Callback || !request->toS3CallbackBytesRemaining) {
        return 0;
    }
    
    // Don't tell the callback that we are willing to accept more data than we
    // really are
    if (len > request->toS3CallbackBytesRemaining) {
        len = request->toS3CallbackBytesRemaining;
    }

	// Otherwise, make the data callback
	int ret;
	if (request->toS3CallbackDataPtr != NULL)
	{
		memcpy((void *)ptr, request->toS3CallbackDataPtr, len);

		request->toS3CallbackDataPtr = (void *)((char *)request->toS3CallbackDataPtr + len);

		ret = len;
	}
	else
	{
		//never reach here
		ret = -1;
// 		// Otherwise, make the data callback
// 		ret = (*(request->toS3Callback))(len, (char *)ptr, request->callbackData);
	}

    if (ret < 0) 
	{
        request->status = S3StatusAbortedByCallback;
        return CURL_READFUNC_ABORT;
    }
    else 
	{
        if (ret > request->toS3CallbackBytesRemaining) 
		{
            ret = request->toS3CallbackBytesRemaining;
        }

        request->toS3CallbackBytesRemaining -= ret;

		if (request->toS3CallbackBytesRemaining <= 0)
		{
			free(request->toS3CallbackData);
			request->toS3CallbackData    = NULL;
			request->toS3CallbackDataPtr = NULL;
		} //if

        return ret;
    }
}


static size_t curl_write_func(void *ptr, size_t size, size_t nmemb,
                              void *data)
{
    Request *request = (Request *) data;

    int len = size * nmemb;

    request_headers_done(request);

    if (request->status != S3StatusOK) {
        return 0;
    }

    // On HTTP error, we expect to parse an HTTP error response
    if ((request->httpResponseCode < 200) || 
        (request->httpResponseCode > 299)) {
        request->status = error_parser_add
            (&(request->errorParser), (char *) ptr, len);
    }
    // If there was a callback registered, make it
    else if (request->fromS3Callback) {
        request->status = (*(request->fromS3Callback))
            (len, (char *) ptr, request->callbackData);
    }
    // Else, consider this an error - S3 has sent back data when it was not
    // expected
    else {
        request->status = S3StatusInternalError;
    }

    return ((request->status == S3StatusOK) ? len : 0);
}


// This function 'normalizes' all x-amz-meta headers provided in
// params->requestHeaders, which means it removes all whitespace from
// them such that they all look exactly like this:
// x-amz-meta-${NAME}: ${VALUE}
// It also adds the x-amz-acl, x-amz-copy-source, x-amz-metadata-directive,
// and x-amz-server-side-encryption headers if necessary, and always adds the
// x-amz-date header.  It copies the raw string values into
// params->amzHeadersRaw, and creates an array of string pointers representing
// these headers in params->amzHeaders (and also sets params->amzHeadersCount
// to be the count of the total number of x-amz- headers thus created).
static S3Status compose_amz_headers(const RequestParams *params,
                                    RequestComputedValues *values)
{
    const S3PutProperties *properties = params->putProperties;

    values->amzHeadersCount = 0;
    values->amzHeadersRaw[0] = 0;
    int len = 0;

    // Append a header to amzHeaders, trimming whitespace from the end.
    // Does NOT trim whitespace from the beginning.
#define headers_append(isNewHeader, format, ...)                        \
    do {                                                                \
        if (isNewHeader) {                                              \
            values->amzHeaders[values->amzHeadersCount++] =             \
                &(values->amzHeadersRaw[len]);                          \
        }                                                               \
        len += snprintf(&(values->amzHeadersRaw[len]),                  \
                        sizeof(values->amzHeadersRaw) - len,            \
                        format, __VA_ARGS__);                           \
        if (len >= (int) sizeof(values->amzHeadersRaw)) {               \
            return S3StatusMetaDataHeadersTooLong;                      \
        }                                                               \
        while ((len > 0) && (values->amzHeadersRaw[len - 1] == ' ')) {  \
            len--;                                                      \
        }                                                               \
        values->amzHeadersRaw[len++] = 0;                               \
    } while (0)

#define header_name_tolower_copy(str, l)                                \
    do {                                                                \
        values->amzHeaders[values->amzHeadersCount++] =                 \
            &(values->amzHeadersRaw[len]);                              \
        if ((len + l) >= (int) sizeof(values->amzHeadersRaw)) {         \
            return S3StatusMetaDataHeadersTooLong;                      \
        }                                                               \
        int todo = l;                                                   \
        while (todo--) {                                                \
            if ((*(str) >= 'A') && (*(str) <= 'Z')) {                   \
                values->amzHeadersRaw[len++] = 'a' + (*(str) - 'A');    \
            }                                                           \
            else {                                                      \
                values->amzHeadersRaw[len++] = *(str);                  \
            }                                                           \
            (str)++;                                                    \
        }                                                               \
    } while (0)

    // Check and copy in the x-amz-meta headers
    if (properties) {
        int i;
        for (i = 0; i < properties->metaDataCount; i++) {
            const S3NameValue *property = &(properties->metaData[i]);
            char headerName[S3_MAX_METADATA_SIZE - sizeof(": v")];
            int l = snprintf(headerName, sizeof(headerName),
                             S3_METADATA_HEADER_NAME_PREFIX "%s",
                             property->name);
            char *hn = headerName;
            header_name_tolower_copy(hn, l);
            // Copy in the value
            headers_append(0, ": %s", property->value);
        }

        // Add the x-amz-acl header, if necessary
        const char *cannedAclString;
        switch (properties->cannedAcl) {
        case S3CannedAclPrivate:
            cannedAclString = 0;
            break;
        case S3CannedAclPublicRead:
            cannedAclString = "public-read";
            break;
        case S3CannedAclPublicReadWrite:
            cannedAclString = "public-read-write";
            break;
        default: // S3CannedAclAuthenticatedRead
            cannedAclString = "authenticated-read";
            break;
        }
        if (cannedAclString) {
            headers_append(1, "x-amz-acl: %s", cannedAclString);
        }

        // Add the x-amz-server-side-encryption header, if necessary
        if (properties->useServerSideEncryption) {
            headers_append(1, "x-amz-server-side-encryption: %s", "AES256");
        }
    }
	
	//-------------------------------------------------------------------------
	// hash payload
	int data_list_block_len = (int)params->toS3CallbackTotalSize;   //int64_t???

	const char *data_list[1];
	if (data_list_block_len > 0 && params->toS3Callback != NULL)
	{
		// read payload
		((RequestParams *)params)->toS3CallbackData = (void *)malloc(params->toS3CallbackTotalSize);
		(*params->toS3Callback)(data_list_block_len,
			(char *)((RequestParams *)params)->toS3CallbackData, params->callbackData);
		data_list[0] = (const char *)(params->toS3CallbackData);
	}
	else
	{
		((RequestParams *)params)->toS3CallbackData = NULL;
		data_list_block_len = 0;
		data_list[0] = "";
	}
	unsigned char hash32[32] = { 0 };
	sha256_vector(1, (const unsigned char **)data_list, &data_list_block_len, hash32);

	values->payload_hexhash[64] = (char)0;
	hexencode((const void *)hash32, sizeof(hash32), values->payload_hexhash);
	headers_append(1, "x-amz-content-sha256: %s", values->payload_hexhash);

#ifdef MY_DEBUG
	printf("\npayload_len = %d\n%s\n\n", data_list_block_len, data_list[0]);
#endif // MY_DEBUG
	
	//-------------------------------------------------------------------------
	
    // Add the x-amz-date header
	values->now = time(NULL);
	char date[64];
	strftime(date, sizeof(date), "%Y%m%dT%H%M%SZ", gmtime(&values->now));
    headers_append(1, "x-amz-date: %s", date);

    if (params->httpRequestType == HttpRequestTypeCOPY) {
        // Add the x-amz-copy-source header
        if (params->copySourceBucketName && params->copySourceBucketName[0] &&
            params->copySourceKey && params->copySourceKey[0]) {
            headers_append(1, "x-amz-copy-source: /%s/%s",
                           params->copySourceBucketName,
                           params->copySourceKey);
        }
        // And the x-amz-metadata-directive header
        if (properties) {
            headers_append(1, "%s", "x-amz-metadata-directive: REPLACE");
        }
    }

    return S3StatusOK;
}


// Composes the other headers
static S3Status compose_standard_headers(const RequestParams *params,
                                         RequestComputedValues *values)
{

#define do_put_header(fmt, sourceField, destField, badError, tooLongError)  \
    do {                                                                    \
        if (params->putProperties &&                                        \
            params->putProperties-> sourceField &&                          \
            params->putProperties-> sourceField[0]) {                       \
            /* Skip whitespace at beginning of val */                       \
            const char *val = params->putProperties-> sourceField;          \
            while (*val && is_blank(*val)) {                                \
                val++;                                                      \
            }                                                               \
            if (!*val) {                                                    \
                return badError;                                            \
            }                                                               \
            /* Compose header, make sure it all fit */                      \
            int len = snprintf(values-> destField,                          \
                               sizeof(values-> destField), fmt, val);       \
            if (len >= (int) sizeof(values-> destField)) {                  \
                return tooLongError;                                        \
            }                                                               \
            /* Now remove the whitespace at the end */                      \
            while (is_blank(values-> destField[len])) {                     \
                len--;                                                      \
            }                                                               \
            values-> destField[len] = 0;                                    \
        }                                                                   \
        else {                                                              \
            values-> destField[0] = 0;                                      \
        }                                                                   \
    } while (0)

#define do_get_header(fmt, sourceField, destField, badError, tooLongError)  \
    do {                                                                    \
        if (params->getConditions &&                                        \
            params->getConditions-> sourceField &&                          \
            params->getConditions-> sourceField[0]) {                       \
            /* Skip whitespace at beginning of val */                       \
            const char *val = params->getConditions-> sourceField;          \
            while (*val && is_blank(*val)) {                                \
                val++;                                                      \
            }                                                               \
            if (!*val) {                                                    \
                return badError;                                            \
            }                                                               \
            /* Compose header, make sure it all fit */                      \
            int len = snprintf(values-> destField,                          \
                               sizeof(values-> destField), fmt, val);       \
            if (len >= (int) sizeof(values-> destField)) {                  \
                return tooLongError;                                        \
            }                                                               \
            /* Now remove the whitespace at the end */                      \
            while (is_blank(values-> destField[len])) {                     \
                len--;                                                      \
            }                                                               \
            values-> destField[len] = 0;                                    \
        }                                                                   \
        else {                                                              \
            values-> destField[0] = 0;                                      \
        }                                                                   \
    } while (0)

    // Cache-Control
    do_put_header("Cache-Control: %s", cacheControl, cacheControlHeader,
                  S3StatusBadCacheControl, S3StatusCacheControlTooLong);
    
    // ContentType
    do_put_header("Content-Type: %s", contentType, contentTypeHeader,
                  S3StatusBadContentType, S3StatusContentTypeTooLong);

    // MD5
    do_put_header("Content-MD5: %s", md5, md5Header, S3StatusBadMD5,
                  S3StatusMD5TooLong);

    // Content-Disposition
    do_put_header("Content-Disposition: attachment; filename=\"%s\"",
                  contentDispositionFilename, contentDispositionHeader,
                  S3StatusBadContentDispositionFilename,
                  S3StatusContentDispositionFilenameTooLong);
    
    // ContentEncoding
    do_put_header("Content-Encoding: %s", contentEncoding, 
                  contentEncodingHeader, S3StatusBadContentEncoding,
                  S3StatusContentEncodingTooLong);
    
    // Expires
    if (params->putProperties && (params->putProperties->expires >= 0)) {
        time_t t = (time_t) params->putProperties->expires;
        strftime(values->expiresHeader, sizeof(values->expiresHeader),
                 "Expires: %a, %d %b %Y %H:%M:%S UTC", gmtime(&t));
    }
    else {
        values->expiresHeader[0] = 0;
    }

    // If-Modified-Since
    if (params->getConditions &&
        (params->getConditions->ifModifiedSince >= 0)) {
        time_t t = (time_t) params->getConditions->ifModifiedSince;
        strftime(values->ifModifiedSinceHeader,
                 sizeof(values->ifModifiedSinceHeader),
                 "If-Modified-Since: %a, %d %b %Y %H:%M:%S UTC", gmtime(&t));
    }
    else {
        values->ifModifiedSinceHeader[0] = 0;
    }

    // If-Unmodified-Since header
    if (params->getConditions &&
        (params->getConditions->ifNotModifiedSince >= 0)) {
        time_t t = (time_t) params->getConditions->ifNotModifiedSince;
        strftime(values->ifUnmodifiedSinceHeader,
                 sizeof(values->ifUnmodifiedSinceHeader),
                 "If-Unmodified-Since: %a, %d %b %Y %H:%M:%S UTC", gmtime(&t));
    }
    else {
        values->ifUnmodifiedSinceHeader[0] = 0;
    }
    
    // If-Match header
    do_get_header("If-Match: %s", ifMatchETag, ifMatchHeader,
                  S3StatusBadIfMatchETag, S3StatusIfMatchETagTooLong);
    
    // If-None-Match header
    do_get_header("If-None-Match: %s", ifNotMatchETag, ifNoneMatchHeader,
                  S3StatusBadIfNotMatchETag, 
                  S3StatusIfNotMatchETagTooLong);
    
    // Range header
    if (params->startByte || params->byteCount) {
        if (params->byteCount) {
            snprintf(values->rangeHeader, sizeof(values->rangeHeader),
                     "Range: bytes=%llu-%llu", 
                     (unsigned long long) params->startByte,
                     (unsigned long long) (params->startByte + 
                                           params->byteCount - 1));
        }
        else {
            snprintf(values->rangeHeader, sizeof(values->rangeHeader),
                     "Range: bytes=%llu-", 
                     (unsigned long long) params->startByte);
        }
    }
    else {
        values->rangeHeader[0] = 0;
    }

    return S3StatusOK;
}


// URL encodes the params->key value into params->urlEncodedKey
static S3Status encode_key(const RequestParams *params,
                           RequestComputedValues *values)
{
    return (urlEncode(values->urlEncodedKey, params->key, S3_MAX_KEY_SIZE) ?
            S3StatusOK : S3StatusUriTooLong);
}


// Simple comparison function for comparing two HTTP header names that are
// embedded within an HTTP header line, returning true if header1 comes
// before header2 alphabetically, false if not
static int headerle(const char *header1, const char *header2)
{
    while (1) {
        if (*header1 == ':') {
            return (*header2 != ':');
        }
        else if (*header2 == ':') {
            return 0;
        }
        else if (*header2 < *header1) {
            return 0;
        }
        else if (*header2 > *header1) {
            return 1;
        }
        header1++, header2++;
    }
}


// Replace this with merge sort eventually, it's the best stable sort.  But
// since typically the number of elements being sorted is small, it doesn't
// matter that much which sort is used, and gnome sort is the world's simplest
// stable sort.  Added a slight twist to the standard gnome_sort - don't go
// forward +1, go forward to the last highest index considered.  This saves
// all the string comparisons that would be done "going forward", and thus
// only does the necessary string comparisons to move values back into their
// sorted position.
static void header_gnome_sort(const char **headers, int size)
{
    int i = 0, last_highest = 0;

    while (i < size) {
        if ((i == 0) || headerle(headers[i - 1], headers[i])) {
            i = ++last_highest;
        }
        else {
            const char *tmp = headers[i];
            headers[i] = headers[i - 1];
            headers[--i] = tmp;
        }
    }
}


// Canonicalizes the x-amz- headers into the canonicalizedAmzHeaders buffer
static void canonicalize_amz_headers(RequestComputedValues *values)
{
    // Make a copy of the headers that will be sorted
    const char *sortedHeaders[S3_MAX_METADATA_COUNT];

    memcpy(sortedHeaders, values->amzHeaders,
           (values->amzHeadersCount * sizeof(sortedHeaders[0])));

    // Now sort these
    header_gnome_sort(sortedHeaders, values->amzHeadersCount);

    // Now copy this sorted list into the buffer, all the while:
    // - folding repeated headers into single lines, and
    // - folding multiple lines
    // - removing the space after the colon
    int lastHeaderLen = 0, i;
    char *buffer = values->canonicalizedAmzHeaders;
    for (i = 0; i < values->amzHeadersCount; ++i) 
	{
        const char *header = sortedHeaders[i];
        const char *c = header;
        // If the header names are the same, append the next value
        if ((i > 0) && !strncmp(header, sortedHeaders[i - 1], lastHeaderLen)) 
		{
            // Replacing the previous newline with a comma
            *(buffer - 1) = ',';
            // Skip the header name and space
            c += (lastHeaderLen + 1);
        }
        // Else this is a new header
        else 
		{
            // Copy in everything up to the space in the ": "
            while (*c != ' ')
			{
                *buffer++ = *c++;
            }
            // Save the header len since it's a new header
            lastHeaderLen = c - header;
            // Skip the space
            c++;
        }
        // Now copy in the value, folding the lines
        while (*c)
		{
            // If c points to a \r\n[whitespace] sequence, then fold
            // this newline out
            if ((*c == '\r') && (*(c + 1) == '\n') && is_blank(*(c + 2))) 
			{
                c += 3;
                while (is_blank(*c)) 
				{
                    c++;
                }
                // Also, what has most recently been copied into buffer amy
                // have been whitespace, and since we're folding whitespace
                // out around this newline sequence, back buffer up over
                // any whitespace it contains
                while (is_blank(*(buffer - 1)))
				{
                    buffer--;
                }
                continue;
            }
            *buffer++ = *c++;
        }
        // Finally, add the newline
        *buffer++ = '\n';
    }

    // Terminate the buffer
    *buffer = 0;
}


// Canonicalizes the resource into params->canonicalizedResource
static void canonicalize_resource(const char *bucketName,
                                  const char *subResource,
                                  const char *urlEncodedKey,
                                  char *buffer)
{
    int len = 0;

    *buffer = 0;

#define append(str) len += sprintf(&(buffer[len]), "%s", str)

    if (bucketName && bucketName[0]) {
        buffer[len++] = '/';
        append(bucketName);
    }

    append("/");

    if (urlEncodedKey && urlEncodedKey[0]) {
        append(urlEncodedKey);
    }

    if (subResource && subResource[0]) {
//         append("?");
//         append(subResource);
    }
}


// Convert an HttpRequestType to an HTTP Verb string
static const char *http_request_type_to_verb(HttpRequestType requestType)
{
    switch (requestType) {
    case HttpRequestTypeGET:
        return "GET";
    case HttpRequestTypeHEAD:
        return "HEAD";
    case HttpRequestTypePUT:
    case HttpRequestTypeCOPY:
        return "PUT";
    default: // HttpRequestTypeDELETE
        return "DELETE";
    }
}


int queryEncode(char *dest, const char *src, int maxSrcSize)
{
	static const char *hex = "0123456789ABCDEF";

	int len = 0;

	if (src) while (*src) {
		if (++len > maxSrcSize) {
			*dest = 0;
			return 0;
		}
		unsigned char c = *src;
		if (isalnum(c) ||
			(c == '-') || (c == '_') || (c == '.') || (c == '!') ||
			(c == '~') || (c == '*') || (c == '\'')/* || (c == '(')*/ ||
			(c == '=')/* || (c == '/')*/) {
			*dest++ = c;
		}
		else if (*src == ' ') {
			*dest++ = '+';
		}
		else {
			*dest++ = '%';
			*dest++ = hex[c >> 4];
			*dest++ = hex[c & 15];
		}
		src++;
	}

	*dest = 0;

	return 1;
}

void generate_signed_headers_by_rrrfff(char *canonicalizedAmzHeaders, char *signed_headers)
{
	char *tmp;
	while (canonicalizedAmzHeaders != NULL && (tmp = strstr(canonicalizedAmzHeaders, ":")) != NULL)
	{
		tmp[0] = '\0';
		strcat(signed_headers, canonicalizedAmzHeaders);
		strcat(signed_headers, ";");
		tmp[0] = ':';
		canonicalizedAmzHeaders = strstr(tmp, "\n");
		if (canonicalizedAmzHeaders != NULL) ++canonicalizedAmzHeaders;
	}
	
	int len = strlen(signed_headers);
	if(len > 0) signed_headers[len - 1] = 0;

#ifdef MY_DEBUG
	printf("\nsignedHeaders(sorted) = \n%s\n", (char *)signed_headers);
#endif // MY_DEBUG
}

void generate_date_by_rrrfff(char *date, const time_t *now)
{
	strftime(date, 32/*sizeof(date)*/, "%Y%m%dT%H%M%SZ", gmtime(now));
}

void generate_scope_by_rrrfff(char *date, char *scope, const time_t *now)
{
	strftime(date, 32/*sizeof(date)*/, "%Y%m%d", gmtime(now));//must here

	//Append the credential scope value
	snprintf(scope, 64/*sizeof(scope)*/, "%s/cn-north-1/s3/aws4_request", date);
}

void generate_signature_v4_by_rrrfff(char *signbuf, char *date, char *scope,
	char *hashed_canonical_request, char *signature, const char *secretAccessKey, const time_t *now)
{
	int len = 0;

	//512 <= sizeof(signbuf)
	#define signbuf_append_ex1(format, ...)             \
    len += snprintf(&(signbuf[len]), 512 - len,     \
                    format, __VA_ARGS__)

	//-------------------------------------------------------------------------
	//create a String to Sign for Signature Version 4

	signbuf_append_ex1("%s\n", "AWS4-HMAC-SHA256");

	//Append the request date value
	generate_date_by_rrrfff(date, now);
	signbuf_append_ex1("%s\n", date);

	generate_scope_by_rrrfff(date, scope, now);
	signbuf_append_ex1("%s\n", scope);

	//Append the hash of the canonical request
	signbuf_append_ex1("%s", hashed_canonical_request);

	// 	string_to_sign
	signbuf[len] = (char)0;

#ifdef MY_DEBUG
	printf("\nSHUN string_to_sign = \n%s\n", signbuf);

	//char string_to_sign_hex[1024];
	//hexencode(signbuf, len, string_to_sign_hex);
	//printf("\nstring_to_sign = \n%s\n", string_to_sign_hex);
#endif // MY_DEBUG


	//-------------------------------------------------------------------------
	//Calculate the AWS Signature Version 4

	//Derive your signing key
	char kSecret[128];
	int kSecret_len = snprintf(kSecret, sizeof(kSecret), "AWS4%s", secretAccessKey);
#ifdef MY_DEBUG
	//printf("\nkSecret = \n%s, Len = %d\n", kSecret, kSecret_len);
#endif

	unsigned char hmac[32];
	HMAC_SHA256(hmac, (unsigned char *)kSecret, kSecret_len, (unsigned char *)date, strlen(date));

	unsigned char hmac_t[32];
	HMAC_SHA256(hmac_t, hmac, 32, (unsigned char *)"cn-north-1", sizeof("cn-north-1") - 1);
	HMAC_SHA256(hmac, hmac_t, 32, (unsigned char *)"s3", sizeof("s3") - 1);
	HMAC_SHA256(hmac_t, hmac, 32, (unsigned char *)"aws4_request", sizeof("aws4_request") - 1);
	HMAC_SHA256(hmac, hmac_t, 32, (unsigned char *)signbuf, len);

	hexencode((const void *)hmac, 32, signature);
	//signature = HexEncode(HMAC(derived-signing-key, string-to-sign))
}

// Composes the Authorization header for the request
static S3Status compose_auth_header(const RequestParams *params,
                                    RequestComputedValues *values)
{
	// We allow for:
	// 17 bytes for HTTP-Verb + \n
	// 129 bytes for Content-MD5 + \n
	// 129 bytes for Content-Type + \n
	// 1 byte for empty Date + \n
	// CanonicalizedAmzHeaders & CanonicalizedResource
	char signbuf[17 + 129 + 129 + 1 +
		(sizeof(values->canonicalizedAmzHeaders) - 1) +
		(sizeof(values->canonicalizedResource) - 1) + 1 + 256];//changed by rrrfff
	int len = 0;

	#define signbuf_append(format, ...)                         \
    len += snprintf(&(signbuf[len]), sizeof(signbuf) - len,     \
                    format, __VA_ARGS__)
	
	
	//-------------------------------------------------------------------------

	signbuf_append
		("%s\n", http_request_type_to_verb(params->httpRequestType));

	signbuf_append("%s\n", values->canonicalizedResource);//e.g. "/"

#ifdef MY_DEBUG
#ifdef MY_DEBUG_ALL
	printf("\ncanonicalizedResource = %s\n", values->canonicalizedResource);//debug only
#endif // MY_DEBUG_ALL
#endif

	if (params->queryParams != NULL && params->queryParams[0])
	{
		char query_encoded[260];
		queryEncode(query_encoded, params->queryParams, strlen(params->queryParams));
		if (params->subResource != NULL && params->subResource[0])
		{
			strcat(query_encoded, "&");
			strcat(query_encoded, params->subResource);
			strcat(query_encoded, "=");
		}
		signbuf_append("%s\n", query_encoded);//empty string is ok
	}
	else
	{
		if (params->subResource != NULL && params->subResource[0])
		{
			signbuf_append("%s=\n", params->subResource);
		}
		else
		{
			signbuf_append("%s\n", "");//empty string is ok
		}
	}

	//Add the canonical headers
	signbuf_append("host:%s\n", params->bucketContext.hostName ? params->bucketContext.hostName : defaultHostNameG);

	signbuf_append("%s\n", values->canonicalizedAmzHeaders);

	//Set the value to STREAMING-AWS4-HMAC-SHA256-PAYLOAD to indicate that the signature covers only headers and that there is no payload.

	//Add signed headers
	char signed_headers[sizeof(values->canonicalizedAmzHeaders)] = { 0 };
	generate_signed_headers_by_rrrfff(values->canonicalizedAmzHeaders, signed_headers);
	signbuf_append("host;%s\n", signed_headers);//to do??

	// payload
	const char *data_list[] = { "" };
//	int data_list_block_len = strlen(data_list[0]);

	unsigned char hash32[32] = { 0 };
//	sha256_vector(1, (const unsigned char **)data_list, &data_list_block_len, hash32);

// 	char hexhash[64 + 1] = { 0 };
// 	hexencode((const void *)hash32, sizeof(hash32), hexhash);
	signbuf_append("%s", values->payload_hexhash);//STREAMING-AWS4-HMAC-SHA256-PAYLOAD

#ifdef MY_DEBUG
	printf("\nsignbuf = \n%s\n", signbuf);//debug only
#endif

	//Create a digest(hash) of the canonical request by using the same algorithm that you
	//	used to hash the payload.

	data_list[0] = signbuf;
	int data_list_block_len = len;

	sha256_vector(1, (const unsigned char **)data_list, &data_list_block_len, hash32);

	char hashed_canonical_request[64 + 1] = { 0 };
	hexencode((const void *)hash32, sizeof(hash32), hashed_canonical_request);

#ifdef MY_DEBUG
	char canonical_request[1024];
	hexencode(signbuf, len, canonical_request);
	printf("\ncanonical_request = \n%s\n", canonical_request);
#endif // MY_DEBUG

	char signature[64 + 1] = { 0 };
	char date[32];
	char scope[64] = { 0 };
	generate_signature_v4_by_rrrfff(signbuf, date, scope, hashed_canonical_request,
		signature, params->bucketContext.secretAccessKey, &values->now);

	snprintf(values->authorizationHeader, sizeof(values->authorizationHeader),
		"Authorization: AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=host;%s, Signature=%s",
		params->bucketContext.accessKeyId, scope, signed_headers, signature);

#ifdef MY_DEBUG
	printf("\n\nvalues->authorizationHeader = %s\n\n", values->authorizationHeader);
#endif
	return S3StatusOK;
}


// Compose the URI to use for the request given the request parameters
static S3Status compose_uri(char *buffer, int bufferSize,
                            const S3BucketContext *bucketContext,
                            const char *urlEncodedKey,
                            const char *subResource, const char *queryParams)
{
    int len = 0;
    
#define uri_append(fmt, ...)                                                 \
    do {                                                                     \
        len += snprintf(&(buffer[len]), bufferSize - len, fmt, __VA_ARGS__); \
        if (len >= bufferSize) {                                             \
            return S3StatusUriTooLong;                                       \
        }                                                                    \
    } while (0)

    uri_append("http%s://", 
               (bucketContext->protocol == S3ProtocolHTTP) ? "" : "s");

    const char *hostName = 
        bucketContext->hostName ? bucketContext->hostName : defaultHostNameG;

    if (bucketContext->bucketName && 
        bucketContext->bucketName[0]) {
        if (bucketContext->uriStyle == S3UriStyleVirtualHost) {
            uri_append("%s.%s", bucketContext->bucketName, hostName);
        }
        else {
            uri_append("%s/%s", hostName, bucketContext->bucketName);
        }
    }
    else {
        uri_append("%s", hostName);
    }

    uri_append("%s", "/");

    uri_append("%s", urlEncodedKey);
    
    if (subResource && subResource[0]) {
        uri_append("?%s", subResource);
    }
    
    if (queryParams) {
        uri_append("%s%s", (subResource && subResource[0]) ? "&" : "?",
                   queryParams);
    }
    
    return S3StatusOK;
}


// Sets up the curl handle given the completely computed RequestParams
static S3Status setup_curl(Request *request,
                           const RequestParams *params,
                           const RequestComputedValues *values)
{
    CURLcode status;

#define curl_easy_setopt_safe(opt, val)                                 \
    if ((status = curl_easy_setopt                                      \
         (request->curl, opt, val)) != CURLE_OK) {                      \
        return S3StatusFailedToInitializeRequest;                       \
    }

    // Debugging only
    // curl_easy_setopt_safe(CURLOPT_VERBOSE, 1);
    
    // Set private data to request for the benefit of S3RequestContext
    curl_easy_setopt_safe(CURLOPT_PRIVATE, request);
    
    // Set header callback and data
    curl_easy_setopt_safe(CURLOPT_HEADERDATA, request);
    curl_easy_setopt_safe(CURLOPT_HEADERFUNCTION, &curl_header_func);
    
    // Set read callback, data, and readSize
    curl_easy_setopt_safe(CURLOPT_READFUNCTION, &curl_read_func);
    curl_easy_setopt_safe(CURLOPT_READDATA, request);
    
    // Set write callback and data
    curl_easy_setopt_safe(CURLOPT_WRITEFUNCTION, &curl_write_func);
    curl_easy_setopt_safe(CURLOPT_WRITEDATA, request);

    // Ask curl to parse the Last-Modified header.  This is easier than
    // parsing it ourselves.
    curl_easy_setopt_safe(CURLOPT_FILETIME, 1);

    // Curl docs suggest that this is necessary for multithreaded code.
    // However, it also points out that DNS timeouts will not be honored
    // during DNS lookup, which can be worked around by using the c-ares
    // library, which we do not do yet.
    curl_easy_setopt_safe(CURLOPT_NOSIGNAL, 1);

    // Turn off Curl's built-in progress meter
    curl_easy_setopt_safe(CURLOPT_NOPROGRESS, 1);

    // xxx todo - support setting the proxy for Curl to use (can't use https
    // for proxies though)

    // xxx todo - support setting the network interface for Curl to use

    // I think this is useful - we don't need interactive performance, we need
    // to complete large operations quickly
    curl_easy_setopt_safe(CURLOPT_TCP_NODELAY, 1);
    
    // Don't use Curl's 'netrc' feature
    curl_easy_setopt_safe(CURLOPT_NETRC, CURL_NETRC_IGNORED);

    // Don't verify S3's certificate, there are known to be issues with
    // them sometimes
    // xxx todo - support an option for verifying the S3 CA (default false)
    curl_easy_setopt_safe(CURLOPT_SSL_VERIFYPEER, 0);

    // Follow any redirection directives that S3 sends
    curl_easy_setopt_safe(CURLOPT_FOLLOWLOCATION, 1);

    // A safety valve in case S3 goes bananas with redirects
    curl_easy_setopt_safe(CURLOPT_MAXREDIRS, 10);

    // Set the User-Agent; maybe Amazon will track these?
    curl_easy_setopt_safe(CURLOPT_USERAGENT, userAgentG);

    // Set the low speed limit and time; we abort transfers that stay at
    // less than 1K per second for more than 15 seconds.
    // xxx todo - make these configurable
    // xxx todo - allow configurable max send and receive speed
    curl_easy_setopt_safe(CURLOPT_LOW_SPEED_LIMIT, 1024);
    curl_easy_setopt_safe(CURLOPT_LOW_SPEED_TIME, 15);

#ifdef MY_DEBUG
	curl_easy_setopt_safe(CURLOPT_VERBOSE, 1);
#endif // MY_DEBUG

    // Append standard headers
#define append_standard_header(fieldName)                               \
    if (values-> fieldName [0]) {                                       \
        request->headers = curl_slist_append(request->headers,          \
                                             values-> fieldName);       \
    }

    // Would use CURLOPT_INFILESIZE_LARGE, but it is buggy in libcurl
    if (params->httpRequestType == HttpRequestTypePUT) {
        char header[256];
        snprintf(header, sizeof(header), "Content-Length: %llu",
                 (unsigned long long) params->toS3CallbackTotalSize);
        request->headers = curl_slist_append(request->headers, header);
        request->headers = curl_slist_append(request->headers, 
                                             "Transfer-Encoding:");
#ifdef MY_DEBUG
		request->headers = curl_slist_append(request->headers,
			"Expect:");
#endif // MY_DEBUG
    }
    else if (params->httpRequestType == HttpRequestTypeCOPY) {
        request->headers = curl_slist_append(request->headers, 
                                             "Transfer-Encoding:");
    }
    
    append_standard_header(cacheControlHeader);
    append_standard_header(contentTypeHeader);
    append_standard_header(md5Header);
    append_standard_header(contentDispositionHeader);
    append_standard_header(contentEncodingHeader);
    append_standard_header(expiresHeader);
    append_standard_header(ifModifiedSinceHeader);
    append_standard_header(ifUnmodifiedSinceHeader);
    append_standard_header(ifMatchHeader);
    append_standard_header(ifNoneMatchHeader);
    append_standard_header(rangeHeader);
    append_standard_header(authorizationHeader);

// 	curl_slist_free_all(request->headers); /* free the header list */
// 
// 	request->headers = NULL;

    // Append x-amz- headers
    int i;
    for (i = 0; i < values->amzHeadersCount; i++) {
        request->headers = 
            curl_slist_append(request->headers, values->amzHeaders[i]);
    }

#ifdef MY_DEBUG
	//curl_slist_append(request->headers, "Date: Wed, 12 Oct 2014 07:30:00 GMT\n");
	//use x-amz-date instead
#endif // _DEBUG

    // Set the HTTP headers
    curl_easy_setopt_safe(CURLOPT_HTTPHEADER, request->headers);

    // Set URI
    curl_easy_setopt_safe(CURLOPT_URL, request->uri);

    // Set request type.
    switch (params->httpRequestType) {
    case HttpRequestTypeHEAD:
    curl_easy_setopt_safe(CURLOPT_NOBODY, 1);
        break;
    case HttpRequestTypePUT:
    case HttpRequestTypeCOPY:
        curl_easy_setopt_safe(CURLOPT_UPLOAD, 1);
        break;
    case HttpRequestTypeDELETE:
    curl_easy_setopt_safe(CURLOPT_CUSTOMREQUEST, "DELETE");
        break;
    default: // HttpRequestTypeGET
        break;
    }
    
    return S3StatusOK;
}


static void request_deinitialize(Request *request)
{
    if (request->headers) {
        curl_slist_free_all(request->headers);
    }
    
    error_parser_deinitialize(&(request->errorParser));

    // curl_easy_reset prevents connections from being re-used for some
    // reason.  This makes HTTP Keep-Alive meaningless and is very bad for
    // performance.  But it is necessary to allow curl to work properly.
    // xxx todo figure out why
    curl_easy_reset(request->curl);
}


static S3Status request_get(const RequestParams *params, 
                            const RequestComputedValues *values,
                            Request **reqReturn)
{
    Request *request = 0;
    
    // Try to get one from the request stack.  We hold the lock for the
    // shortest time possible here.
    pthread_mutex_lock(&requestStackMutexG);

    if (requestStackCountG) {
        request = requestStackG[--requestStackCountG];
    }
    
    pthread_mutex_unlock(&requestStackMutexG);

    // If we got one, deinitialize it for re-use
    if (request) {
        request_deinitialize(request);
    }
    // Else there wasn't one available in the request stack, so create one
    else {
        if (!(request = (Request *) malloc(sizeof(Request)))) {
            return S3StatusOutOfMemory;
        }
        if (!(request->curl = curl_easy_init())) {
            free(request);
            return S3StatusFailedToInitializeRequest;
        }
    }

    // Initialize the request
    request->prev = 0;
    request->next = 0;

    // Request status is initialized to no error, will be updated whenever
    // an error occurs
    request->status = S3StatusOK;

    S3Status status;
                        
    // Start out with no headers
    request->headers = 0;

    // Compute the URL
    if ((status = compose_uri
         (request->uri, sizeof(request->uri), 
          &(params->bucketContext), values->urlEncodedKey,
          params->subResource, params->queryParams)) != S3StatusOK) {
        curl_easy_cleanup(request->curl);
        free(request);
        return status;
    }

    // Set all of the curl handle options
    if ((status = setup_curl(request, params, values)) != S3StatusOK) {
        curl_easy_cleanup(request->curl);
        free(request);
        return status;
    }

    request->propertiesCallback = params->propertiesCallback;

    request->toS3Callback = params->toS3Callback;

	request->toS3CallbackData = (void *)(params->toS3CallbackData);

	request->toS3CallbackDataPtr = request->toS3CallbackData;

    request->toS3CallbackBytesRemaining = params->toS3CallbackTotalSize;

    request->fromS3Callback = params->fromS3Callback;

    request->completeCallback = params->completeCallback;

    request->callbackData = params->callbackData;

    response_headers_handler_initialize(&(request->responseHeadersHandler));

    request->propertiesCallbackMade = 0;
    
    error_parser_initialize(&(request->errorParser));

    *reqReturn = request;
    
    return S3StatusOK;
}


static void request_destroy(Request *request)
{
    request_deinitialize(request);
    curl_easy_cleanup(request->curl);
    free(request);
}


static void request_release(Request *request)
{
    pthread_mutex_lock(&requestStackMutexG);

    // If the request stack is full, destroy this one
    if (requestStackCountG == REQUEST_STACK_SIZE) {
        pthread_mutex_unlock(&requestStackMutexG);
        request_destroy(request);
    }
    // Else put this one at the front of the request stack; we do this because
    // we want the most-recently-used curl handle to be re-used on the next
    // request, to maximize our chances of re-using a TCP connection before it
    // times out
    else {
        requestStackG[requestStackCountG++] = request;
        pthread_mutex_unlock(&requestStackMutexG);
    }
}


S3Status request_api_initialize(const char *userAgentInfo, int flags,
                                const char *defaultHostName)
{
    if (curl_global_init(CURL_GLOBAL_ALL & 
                         ~((flags & S3_INIT_WINSOCK) ? 0 : CURL_GLOBAL_WIN32))
        != CURLE_OK) {
        return S3StatusInternalError;
    }

    if (!defaultHostName) {
        defaultHostName = S3_DEFAULT_HOSTNAME;
    }

    if (snprintf(defaultHostNameG, S3_MAX_HOSTNAME_SIZE, 
                 "%s", defaultHostName) >= S3_MAX_HOSTNAME_SIZE) {
        return S3StatusUriTooLong;
    }

    pthread_mutex_init(&requestStackMutexG, 0);

    requestStackCountG = 0;

    if (!userAgentInfo || !*userAgentInfo) {
        userAgentInfo = "Unknown";
    }

    char platform[96];
    struct utsname utsn;
    if (uname(&utsn)) {
        strncpy(platform, "Unknown", sizeof(platform));
        // Because strncpy doesn't always zero terminate
        platform[sizeof(platform) - 1] = 0;
    }
    else {
        snprintf(platform, sizeof(platform), "%s%s%s", utsn.sysname, 
                 utsn.machine[0] ? " " : "", utsn.machine);
    }

    snprintf(userAgentG, sizeof(userAgentG), 
             "Mozilla/4.0 (Compatible; %s; libs3 %s.%s; %s)",
             userAgentInfo, LIBS3_VER_MAJOR, LIBS3_VER_MINOR, platform);
    
    return S3StatusOK;
}


void request_api_deinitialize()
{
    pthread_mutex_destroy(&requestStackMutexG);

    while (requestStackCountG--) {
        request_destroy(requestStackG[requestStackCountG]);
    }
}


void request_perform(const RequestParams *params, S3RequestContext *context)
{
	((RequestParams *)params)->toS3CallbackData = NULL;

    Request *request;
    S3Status status;

#define return_status(status)                                           \
    (*(params->completeCallback))(status, 0, params->callbackData);     \
    return

    // These will hold the computed values
    RequestComputedValues computed;

    // Validate the bucket name
    if (params->bucketContext.bucketName && 
        ((status = S3_validate_bucket_name
          (params->bucketContext.bucketName, 
           params->bucketContext.uriStyle)) != S3StatusOK)) {
        return_status(status);
    }

    // Compose the amz headers
    if ((status = compose_amz_headers(params, &computed)) != S3StatusOK) {
        return_status(status);
    }

    // Compose standard headers
    if ((status = compose_standard_headers
         (params, &computed)) != S3StatusOK) {
        return_status(status);
    }

    // URL encode the key
    if ((status = encode_key(params, &computed)) != S3StatusOK) {
        return_status(status);
    }

    // Compute the canonicalized amz headers
    canonicalize_amz_headers(&computed);

    // Compute the canonicalized resource
    canonicalize_resource(params->bucketContext.bucketName,
                          params->subResource, computed.urlEncodedKey,
                          computed.canonicalizedResource);

    // Compose Authorization header
    if ((status = compose_auth_header(params, &computed)) != S3StatusOK) {
        return_status(status);
    }
    
    // Get an initialized Request structure now
    if ((status = request_get(params, &computed, &request)) != S3StatusOK) {
        return_status(status);
    }

    // If a RequestContext was provided, add the request to the curl multi
    if (context)
	{
        CURLMcode code = curl_multi_add_handle(context->curlm, request->curl);
        if (code == CURLM_OK) 
		{
            if (context->requests)
			{
                request->prev = context->requests->prev;
                request->next = context->requests;
                context->requests->prev->next = request;
                context->requests->prev = request;
            }
            else 
			{
                context->requests = request->next = request->prev = request;
            }
        }
        else
		{
            if (request->status == S3StatusOK) 
			{
                request->status = (code == CURLM_OUT_OF_MEMORY) ?
                    S3StatusOutOfMemory : S3StatusInternalError;
            }
            request_finish(request);
        }
    }
    // Else, perform the request immediately
    else 
	{
		
        CURLcode code = curl_easy_perform(request->curl);
        if ((code != CURLE_OK) && (request->status == S3StatusOK)) {
            request->status = request_curl_code_to_status(code);
        }
        // Finish the request, ensuring that all callbacks have been made, and
        // also releases the request
        request_finish(request);
    }
}


void request_finish(Request *request)
{
    // If we haven't detected this already, we now know that the headers are
    // definitely done being read in
    request_headers_done(request);
    
    // If there was no error processing the request, then possibly there was
    // an S3 error parsed, which should be converted into the request status
    if (request->status == S3StatusOK) {
        error_parser_convert_status(&(request->errorParser), 
                                    &(request->status));
        // If there still was no error recorded, then it is possible that
        // there was in fact an error but that there was no error XML
        // detailing the error
        if ((request->status == S3StatusOK) &&
            ((request->httpResponseCode < 200) ||
             (request->httpResponseCode > 299))) {
            switch (request->httpResponseCode) {
            case 0:
                // This happens if the request never got any HTTP response
                // headers at all, we call this a ConnectionFailed error
                request->status = S3StatusConnectionFailed;
                break;
            case 100: // Some versions of libcurl erroneously set HTTP
                      // status to this
                break;
            case 301:
                request->status = S3StatusErrorPermanentRedirect;
                break;
            case 307:
                request->status = S3StatusHttpErrorMovedTemporarily;
                break;
            case 400:
                request->status = S3StatusHttpErrorBadRequest;
                break;
            case 403: 
                request->status = S3StatusHttpErrorForbidden;
                break;
            case 404:
                request->status = S3StatusHttpErrorNotFound;
                break;
            case 405:
                request->status = S3StatusErrorMethodNotAllowed;
                break;
            case 409:
                request->status = S3StatusHttpErrorConflict;
                break;
            case 411:
                request->status = S3StatusErrorMissingContentLength;
                break;
            case 412:
                request->status = S3StatusErrorPreconditionFailed;
                break;
            case 416:
                request->status = S3StatusErrorInvalidRange;
                break;
            case 500:
                request->status = S3StatusErrorInternalError;
                break;
            case 501:
                request->status = S3StatusErrorNotImplemented;
                break;
            case 503:
                request->status = S3StatusErrorSlowDown;
                break;
            default:
                request->status = S3StatusHttpErrorUnknown;
                break;
            }
        }
    }

    (*(request->completeCallback))
        (request->status, &(request->errorParser.s3ErrorDetails),
         request->callbackData);

    request_release(request);
}


S3Status request_curl_code_to_status(CURLcode code)
{
    switch (code) {
    case CURLE_OUT_OF_MEMORY:
        return S3StatusOutOfMemory;
    case CURLE_COULDNT_RESOLVE_PROXY:
    case CURLE_COULDNT_RESOLVE_HOST:
        return S3StatusNameLookupError;
    case CURLE_COULDNT_CONNECT:
        return S3StatusFailedToConnect;
    case CURLE_WRITE_ERROR:
    case CURLE_OPERATION_TIMEDOUT:
        return S3StatusConnectionFailed;
    case CURLE_PARTIAL_FILE:
        return S3StatusOK;
    case CURLE_SSL_CACERT:
        return S3StatusServerFailedVerification;
    default:
        return S3StatusInternalError;
    }
}


S3Status S3_generate_authenticated_query_string
    (char *buffer, const S3BucketContext *bucketContext,
     const char *key, int64_t expires, const char *resource)
{
	    #define MAX_EXPIRES 604800
		// S3 seems to only accept expiration dates up to the number of seconds
		// representably by a signed 32-bit integer
	    // The minimum value you can set is 1, and the maximum is 604800 (seven days).
		if (expires < 1) 
		{
			expires = MAX_EXPIRES;
		}
		else if (expires > MAX_EXPIRES) 
		{
			expires = MAX_EXPIRES;
		}

		// URL encode the key
		char urlEncodedKey[S3_MAX_KEY_SIZE * 3];
		if (key) 
		{
			urlEncode(urlEncodedKey, key, strlen(key));
		}
		else 
		{
			urlEncodedKey[0] = 0;
		}

		// Compute canonicalized resource
		char canonicalizedResource[MAX_CANONICALIZED_RESOURCE_SIZE];
		//canonicalize_resource(bucketContext->bucketName, resource, urlEncodedKey,
		//	canonicalizedResource);
                sprintf(canonicalizedResource, "/%s", urlEncodedKey);

		// We allow for:
		// 17 bytes for HTTP-Verb + \n
		// 20 bytes for Expires + \n
		// 0 bytes for CanonicalizedAmzHeaders
		// CanonicalizedResource
		char signbuf[17 + 1 + 20 + sizeof(canonicalizedResource) + 1 + 512];//changed by rrrfff
		int len = 0;

#define signbuf_append(format, ...)                             \
    len += snprintf(&(signbuf[len]), sizeof(signbuf) - len,     \
                    format, __VA_ARGS__)

		
		//-------------------------------------------------------------------------
		//CanonicalRequest
		signbuf_append("%s\n", "GET"); // HTTP-Verb
		signbuf_append("%s\n", canonicalizedResource);

		time_t now = time(NULL);
		char date[32];
		char scope[64] = { 0 };
		generate_date_by_rrrfff(date, &now);
		char date_short[8 + 1];
		generate_scope_by_rrrfff(date_short, scope, &now);

		//url encoded scope
		char scope_urlencoded[128] = {"%2F"};
		//urlEncode(scope_urlencoded + 3, scope, strlen(scope));
                snprintf(scope_urlencoded + 3, 128-3/*sizeof(scope)*/, "%s%%2Fcn-north-1%%2Fs3%%2Faws4_request", date_short);

		char sub_resource[128] = {0};
		if (resource != NULL)
		{
			snprintf(sub_resource, sizeof(sub_resource), "%s&", resource);
		} //if

		char queryParams[260];
		snprintf(queryParams, sizeof(queryParams),
			"X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=%s%s&X-Amz-Date=%s&X-Amz-Expires=%ld&X-Amz-SignedHeaders=host",
			bucketContext->accessKeyId, scope_urlencoded, date, (long)expires);
		//to do: sort the querystring
                char HostNameG[128] = {0};
                sprintf(HostNameG, "%s.%s", bucketContext->bucketName, defaultHostNameG);
		signbuf_append("%s%s\nhost:%s\n", sub_resource, queryParams, (bucketContext->hostName ? bucketContext->hostName : HostNameG));
		//signbuf_append("x-amz-date:%s\n", date);

		signbuf_append("\nhost\n%s", "UNSIGNED-PAYLOAD");

#ifdef MY_DEBUG
		printf("\nSHUN signbuf = \n%s\n", signbuf);
#endif // _DEBUG

		// Generate an SHA-256 of the signbuf
		const char *data_list[] = { signbuf };
		unsigned char hash32[32] = { 0 };
		sha256_vector(1, (const unsigned char **)data_list, &len, hash32);

		char hexhash[64 + 1] = { 0 };
		hexencode((const void *)hash32, sizeof(hash32), hexhash);

		//-------------------------------------------------------------------------
		
		char signature[64 + 1] = { 0 };
		generate_signature_v4_by_rrrfff(signbuf, date, scope, hexhash,
			signature, bucketContext->secretAccessKey, &now);

		len = 0;
		signbuf_append("%s&X-Amz-Signature=%s", queryParams, signature);

		//-------------------------------------------------------------------------
		// Finally, compose the uri, with params:
		return compose_uri(buffer, S3_MAX_AUTHENTICATED_QUERY_STRING_SIZE,
			bucketContext, urlEncodedKey, resource, signbuf/*queryParams*/);
}
