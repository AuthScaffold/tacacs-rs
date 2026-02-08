/**
 * TACACS-rs FFI Simple Example
 * 
 * Demonstrates basic usage of the TACACS-rs FFI library from C.
 * This example shows how to:
 * - Create TACACS+ headers
 * - Create TACACS+ packets
 * - Serialize packets to bytes
 * - Proper memory management
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../include/tacacs.h"

int main(void) {
    tacacs_TacacsError error;
    
    printf("=== TACACS-rs FFI Simple Example ===\n\n");
    
    // Create a TACACS+ header
    printf("1. Creating TACACS+ header...\n");
    tacacs_TacacsHeader* header = tacacs_header_new(
        TACACS_C_TACACS_MAJOR_VERSION_TACACS_PLUS_MAJOR1,
        TACACS_C_TACACS_MINOR_VERSION_TACACS_PLUS_MINOR_VER_ONE,
        TACACS_C_TACACS_TYPE_TAC_PLUS_AUTHENTICATION,
        1,                              // seq_no
        tacacs_TACACS_FLAG_UNENCRYPTED, // flags
        12345,                          // session_id
        11,                             // length
        &error
    );
    
    if (header == NULL) {
        fprintf(stderr, "Failed to create header: %s\n", error.message);
        tacacs_free_error_message(error.message);
        return 1;
    }
    
    printf("   Header created successfully!\n");
    printf("   Session ID: %u\n", tacacs_header_get_session_id(header));
    printf("   Sequence Number: %u\n", tacacs_header_get_seq_no(header));
    printf("   Length: %u\n\n", tacacs_header_get_length(header));
    
    // Create a TACACS+ packet with a simple body
    printf("2. Creating TACACS+ packet...\n");
    const char* body_text = "Hello TACACS";
    tacacs_TacacsPacket* packet = tacacs_packet_new(
        header,
        (const uint8_t*)body_text,
        strlen(body_text),
        &error
    );
    
    if (packet == NULL) {
        fprintf(stderr, "Failed to create packet: %s\n", error.message);
        tacacs_free_error_message(error.message);
        tacacs_header_free(header);
        return 1;
    }
    
    printf("   Packet created successfully!\n\n");
    
    // Serialize the packet to bytes
    printf("3. Serializing packet to bytes...\n");
    size_t out_len = 0;
    uint8_t* buffer = tacacs_packet_to_bytes(packet, &out_len, &error);
    
    if (buffer == NULL) {
        fprintf(stderr, "Failed to serialize packet: %s\n", error.message);
        tacacs_free_error_message(error.message);
        tacacs_packet_free(packet);
        tacacs_header_free(header);
        return 1;
    }
    
    printf("   Serialization successful!\n");
    printf("   Buffer size: %zu bytes\n", out_len);
    printf("   First 12 bytes (header): ");
    for (size_t i = 0; i < 12 && i < out_len; i++) {
        printf("%02x ", buffer[i]);
    }
    printf("\n\n");
    
    // Test obfuscation
    printf("4. Testing packet obfuscation...\n");
    const char* key = "secret_key";
    tacacs_TacacsPacket* obfuscated = tacacs_packet_obfuscate(
        packet,
        (const uint8_t*)key,
        strlen(key),
        &error
    );
    
    if (obfuscated == NULL) {
        fprintf(stderr, "Failed to obfuscate packet: %s\n", error.message);
        tacacs_free_error_message(error.message);
    } else {
        printf("   Packet obfuscated successfully!\n");
        
        // Deobfuscate it back
        tacacs_TacacsPacket* deobfuscated = tacacs_packet_deobfuscate(
            obfuscated,
            (const uint8_t*)key,
            strlen(key),
            &error
        );
        
        if (deobfuscated != NULL) {
            printf("   Packet deobfuscated successfully!\n");
            tacacs_packet_free(deobfuscated);
        }
        
        tacacs_packet_free(obfuscated);
    }
    printf("\n");
    
    // Clean up
    printf("5. Cleaning up resources...\n");
    tacacs_free_bytes(buffer);
    tacacs_packet_free(packet);
    tacacs_header_free(header);
    
    printf("   All resources freed successfully!\n\n");
    printf("=== Example completed successfully! ===\n");
    
    return 0;
}
