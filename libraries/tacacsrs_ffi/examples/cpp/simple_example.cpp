/**
 * TACACS-rs FFI C++ Example
 * 
 * Demonstrates usage of the TACACS-rs FFI library from C++.
 * This example uses RAII principles for automatic resource management.
 */

#include <iostream>
#include <memory>
#include <string>
#include <cstring>
#include <iomanip>

extern "C" {
#include "../../include/tacacs.h"
}

// RAII wrapper for TACACS+ header
class TacacsHeaderWrapper {
public:
    TacacsHeaderWrapper(tacacs_TacacsHeader* header) : header_(header) {}
    
    ~TacacsHeaderWrapper() {
        if (header_) {
            tacacs_header_free(header_);
        }
    }
    
    // Delete copy constructor and assignment operator
    TacacsHeaderWrapper(const TacacsHeaderWrapper&) = delete;
    TacacsHeaderWrapper& operator=(const TacacsHeaderWrapper&) = delete;
    
    // Allow move
    TacacsHeaderWrapper(TacacsHeaderWrapper&& other) noexcept : header_(other.header_) {
        other.header_ = nullptr;
    }
    
    tacacs_TacacsHeader* get() const { return header_; }
    
    uint32_t getSessionId() const {
        return tacacs_header_get_session_id(header_);
    }
    
    uint8_t getSeqNo() const {
        return tacacs_header_get_seq_no(header_);
    }
    
    uint32_t getLength() const {
        return tacacs_header_get_length(header_);
    }

private:
    tacacs_TacacsHeader* header_;
};

// RAII wrapper for TACACS+ packet
class TacacsPacketWrapper {
public:
    TacacsPacketWrapper(tacacs_TacacsPacket* packet) : packet_(packet) {}
    
    ~TacacsPacketWrapper() {
        if (packet_) {
            tacacs_packet_free(packet_);
        }
    }
    
    // Delete copy constructor and assignment operator
    TacacsPacketWrapper(const TacacsPacketWrapper&) = delete;
    TacacsPacketWrapper& operator=(const TacacsPacketWrapper&) = delete;
    
    // Allow move
    TacacsPacketWrapper(TacacsPacketWrapper&& other) noexcept : packet_(other.packet_) {
        other.packet_ = nullptr;
    }
    
    tacacs_TacacsPacket* get() const { return packet_; }

private:
    tacacs_TacacsPacket* packet_;
};

// RAII wrapper for byte buffer
class ByteBufferWrapper {
public:
    ByteBufferWrapper(uint8_t* buffer, size_t size) : buffer_(buffer), size_(size) {}
    
    ~ByteBufferWrapper() {
        if (buffer_) {
            tacacs_free_bytes(buffer_);
        }
    }
    
    // Delete copy constructor and assignment operator
    ByteBufferWrapper(const ByteBufferWrapper&) = delete;
    ByteBufferWrapper& operator=(const ByteBufferWrapper&) = delete;
    
    const uint8_t* data() const { return buffer_; }
    size_t size() const { return size_; }

private:
    uint8_t* buffer_;
    size_t size_;
};

int main() {
    std::cout << "=== TACACS-rs FFI C++ Example ===" << std::endl << std::endl;
    
    try {
        // Create a TACACS+ header
        std::cout << "1. Creating TACACS+ header..." << std::endl;
        tacacs_TacacsError error;
        
        tacacs_TacacsHeader* raw_header = tacacs_header_new(
            TACACS_C_TACACS_MAJOR_VERSION_TACACS_PLUS_MAJOR1,
            TACACS_C_TACACS_MINOR_VERSION_TACACS_PLUS_MINOR_VER_ONE,
            TACACS_C_TACACS_TYPE_TAC_PLUS_AUTHENTICATION,
            1,                              // seq_no
            tacacs_TACACS_FLAG_UNENCRYPTED, // flags
            54321,                          // session_id
            13,                             // length
            &error
        );
        
        if (raw_header == nullptr) {
            std::cerr << "Failed to create header: " << error.message << std::endl;
            tacacs_free_error_message(error.message);
            return 1;
        }
        
        TacacsHeaderWrapper header(raw_header);
        std::cout << "   Header created successfully!" << std::endl;
        std::cout << "   Session ID: " << header.getSessionId() << std::endl;
        std::cout << "   Sequence Number: " << static_cast<int>(header.getSeqNo()) << std::endl;
        std::cout << "   Length: " << header.getLength() << std::endl << std::endl;
        
        // Create a TACACS+ packet
        std::cout << "2. Creating TACACS+ packet..." << std::endl;
        std::string body_text = "Hello, TACACS!";
        
        tacacs_TacacsPacket* raw_packet = tacacs_packet_new(
            header.get(),
            reinterpret_cast<const uint8_t*>(body_text.c_str()),
            body_text.length(),
            &error
        );
        
        if (raw_packet == nullptr) {
            std::cerr << "Failed to create packet: " << error.message << std::endl;
            tacacs_free_error_message(error.message);
            return 1;
        }
        
        TacacsPacketWrapper packet(raw_packet);
        std::cout << "   Packet created successfully!" << std::endl << std::endl;
        
        // Serialize the packet
        std::cout << "3. Serializing packet to bytes..." << std::endl;
        size_t out_len = 0;
        uint8_t* raw_buffer = tacacs_packet_to_bytes(packet.get(), &out_len, &error);
        
        if (raw_buffer == nullptr) {
            std::cerr << "Failed to serialize packet: " << error.message << std::endl;
            tacacs_free_error_message(error.message);
            return 1;
        }
        
        ByteBufferWrapper buffer(raw_buffer, out_len);
        std::cout << "   Serialization successful!" << std::endl;
        std::cout << "   Buffer size: " << buffer.size() << " bytes" << std::endl;
        std::cout << "   First 12 bytes (header): ";
        
        std::cout << std::hex << std::setfill('0');
        for (size_t i = 0; i < 12 && i < buffer.size(); i++) {
            std::cout << std::setw(2) << static_cast<int>(buffer.data()[i]) << " ";
        }
        std::cout << std::dec << std::endl << std::endl;
        
        // Test obfuscation
        std::cout << "4. Testing packet obfuscation..." << std::endl;
        std::string key = "my_secret_key";
        
        tacacs_TacacsPacket* raw_obfuscated = tacacs_packet_obfuscate(
            packet.get(),
            reinterpret_cast<const uint8_t*>(key.c_str()),
            key.length(),
            &error
        );
        
        if (raw_obfuscated == nullptr) {
            std::cerr << "Failed to obfuscate packet: " << error.message << std::endl;
            tacacs_free_error_message(error.message);
        } else {
            TacacsPacketWrapper obfuscated(raw_obfuscated);
            std::cout << "   Packet obfuscated successfully!" << std::endl;
            
            // Deobfuscate it back
            tacacs_TacacsPacket* raw_deobfuscated = tacacs_packet_deobfuscate(
                obfuscated.get(),
                reinterpret_cast<const uint8_t*>(key.c_str()),
                key.length(),
                &error
            );
            
            if (raw_deobfuscated != nullptr) {
                TacacsPacketWrapper deobfuscated(raw_deobfuscated);
                std::cout << "   Packet deobfuscated successfully!" << std::endl;
            }
        }
        std::cout << std::endl;
        
        std::cout << "5. Cleaning up resources..." << std::endl;
        std::cout << "   Resources will be automatically freed by RAII wrappers!" << std::endl << std::endl;
        
        std::cout << "=== Example completed successfully! ===" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
