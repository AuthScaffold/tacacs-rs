/**
 * TACACS-rs FFI Accounting Example
 * 
 * Demonstrates usage of TACACS+ accounting messages from C.
 * This example shows how to:
 * - Create accounting requests
 * - Create accounting replies
 * - Serialize to bytes
 * - Parse from packets
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../include/tacacs.h"

int main(void) {
    tacacs_TacacsError error;
    
    printf("=== TACACS-rs FFI Accounting Example ===\n\n");
    
    // 1. Create an accounting request
    printf("1. Creating accounting request...\n");
    
    tacacs_TacacsAccountingRequest* request = tacacs_accounting_request_new(
        tacacs_TACACS_ACCOUNTING_FLAG_START,
        TACACS_C_TACACS_AUTHENTICATION_METHOD_TAC_PLUS_AUTHEN_METHOD_LOCAL,
        15,  // privilege level
        TACACS_C_TACACS_AUTHENTICATION_TYPE_TAC_PLUS_AUTHEN_TYPE_ASCII,
        TACACS_C_TACACS_AUTHENTICATION_SERVICE_TAC_PLUS_AUTHEN_SVC_LOGIN,
        "testuser",
        "tty1",
        "192.168.1.100",
        NULL,  // no args
        0,     // args count
        &error
    );
    
    if (request == NULL) {
        fprintf(stderr, "Failed to create request: %s\n", error.message);
        tacacs_free_error_message(error.message);
        return 1;
    }
    
    printf("   Request created successfully!\n");
    
    // Get and display request fields
    char* user = tacacs_accounting_request_get_user(request);
    char* port = tacacs_accounting_request_get_port(request);
    char* rem_addr = tacacs_accounting_request_get_rem_address(request);
    uint8_t priv_lvl = tacacs_accounting_request_get_priv_lvl(request);
    uint8_t flags = tacacs_accounting_request_get_flags(request);
    
    printf("   User: %s\n", user);
    printf("   Port: %s\n", port);
    printf("   Remote Address: %s\n", rem_addr);
    printf("   Privilege Level: %u\n", priv_lvl);
    printf("   Flags: 0x%02x\n\n", flags);
    
    tacacs_free_string(user);
    tacacs_free_string(port);
    tacacs_free_string(rem_addr);
    
    // 2. Serialize the request to bytes
    printf("2. Serializing accounting request to bytes...\n");
    size_t request_len = 0;
    uint8_t* request_bytes = tacacs_accounting_request_to_bytes(request, &request_len, &error);
    
    if (request_bytes == NULL) {
        fprintf(stderr, "Failed to serialize request: %s\n", error.message);
        tacacs_free_error_message(error.message);
        tacacs_accounting_request_free(request);
        return 1;
    }
    
    printf("   Serialization successful!\n");
    printf("   Request size: %zu bytes\n", request_len);
    printf("   First 16 bytes: ");
    for (size_t i = 0; i < 16 && i < request_len; i++) {
        printf("%02x ", request_bytes[i]);
    }
    printf("\n\n");
    
    tacacs_free_bytes(request_bytes);
    
    // 3. Create an accounting reply
    printf("3. Creating accounting reply...\n");
    
    tacacs_TacacsAccountingReply* reply = tacacs_accounting_reply_new(
        TACACS_C_TACACS_ACCOUNTING_STATUS_TAC_PLUS_ACCT_STATUS_SUCCESS,
        "Accounting successful",
        "",
        &error
    );
    
    if (reply == NULL) {
        fprintf(stderr, "Failed to create reply: %s\n", error.message);
        tacacs_free_error_message(error.message);
        tacacs_accounting_request_free(request);
        return 1;
    }
    
    printf("   Reply created successfully!\n");
    
    // Get and display reply fields
    enum tacacs_CTacacsAccountingStatus status = tacacs_accounting_reply_get_status(reply);
    char* server_msg = tacacs_accounting_reply_get_server_msg(reply);
    char* data = tacacs_accounting_reply_get_data(reply);
    
    printf("   Status: %s\n", 
           status == TACACS_C_TACACS_ACCOUNTING_STATUS_TAC_PLUS_ACCT_STATUS_SUCCESS ? "SUCCESS" :
           status == TACACS_C_TACACS_ACCOUNTING_STATUS_TAC_PLUS_ACCT_STATUS_ERROR ? "ERROR" : "FOLLOW");
    printf("   Server Message: %s\n", server_msg);
    printf("   Data: %s\n\n", data);
    
    tacacs_free_string(server_msg);
    tacacs_free_string(data);
    
    // 4. Serialize the reply to bytes
    printf("4. Serializing accounting reply to bytes...\n");
    size_t reply_len = 0;
    uint8_t* reply_bytes = tacacs_accounting_reply_to_bytes(reply, &reply_len, &error);
    
    if (reply_bytes == NULL) {
        fprintf(stderr, "Failed to serialize reply: %s\n", error.message);
        tacacs_free_error_message(error.message);
        tacacs_accounting_reply_free(reply);
        tacacs_accounting_request_free(request);
        return 1;
    }
    
    printf("   Serialization successful!\n");
    printf("   Reply size: %zu bytes\n", reply_len);
    printf("   All bytes: ");
    for (size_t i = 0; i < reply_len; i++) {
        printf("%02x ", reply_bytes[i]);
    }
    printf("\n\n");
    
    tacacs_free_bytes(reply_bytes);
    
    // 5. Clean up
    printf("5. Cleaning up resources...\n");
    tacacs_accounting_reply_free(reply);
    tacacs_accounting_request_free(request);
    
    printf("   All resources freed successfully!\n\n");
    printf("=== Example completed successfully! ===\n");
    
    return 0;
}
