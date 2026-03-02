workspace "flarelette-crypto" "Post-quantum hybrid envelope encryption library" {

    model {
        # flarelette-crypto System
        flarelette_crypto = softwareSystem "flarelette-crypto" {
            description "Post-quantum hybrid envelope encryption library"
            # Containers




            chrislyons_dev_flarelette_crypto = container "@chrislyons-dev/flarelette-crypto" {
                description "Post-quantum hybrid envelope encryption for Cloudflare Workers, browsers, and Node.js"
                technology "Service"
                tags "Service,Auto-generated"

                # Components
                chrislyons_dev_flarelette_crypto__src = component "src" {
                    description "Component inferred from directory: src"
                    technology "module"
                }

                # Code elements (classes, functions)
                chrislyons_dev_flarelette_crypto__src__generatechannelkey = component "src.generateChannelKey" {
                    description "Generate a random 32-byte channel key. Pass this to encapsulateChannelKey() for each channel member, then use it with encryptDoc() to encrypt documents. Keep it in memory only — never serialise it. To add a new member later, call encapsulateChannelKey() again with the same key."
                    technology "function"
                    tags "Code"
                }
                chrislyons_dev_flarelette_crypto__src__encapsulatechannelkey = component "src.encapsulateChannelKey" {
                    description "Wrap a channel key for one recipient using hybrid ML-KEM-1024 + X25519. Security properties: - Channel binding: a returned ChannelEncapsulation is only valid for the given channelId. - Recipient binding: only the holder of the matching ChannelKeypairs secret key can recover the channel key via decapsulateChannelKey(). - Forward secrecy (classical): ephemeral X25519 key is discarded after encapsulation."
                    technology "function"
                    tags "Code"
                }
                chrislyons_dev_flarelette_crypto__src__decapsulatechannelkey = component "src.decapsulateChannelKey" {
                    description "Recover a channel key from a ChannelEncapsulation using the recipient's secret key. Verifies channel binding — decapsulation fails if the channelId does not match the one used during encapsulateChannelKey(). This is enforced cryptographically via the HKDF info parameter: a mismatched channelId produces a different wrap key, causing AES-GCM decryption to fail."
                    technology "function"
                    tags "Code"
                }
                chrislyons_dev_flarelette_crypto__src__derivekey = component "src.deriveKey" {
                    description "Derive a key using HKDF-SHA512."
                    technology "function"
                    tags "Code"
                }
                chrislyons_dev_flarelette_crypto__src__encryptdoc = component "src.encryptDoc" {
                    description "Encrypt plaintext with a channel key. The channel key (masterKey) is never serialised by this function — it is the caller's responsibility to keep it in memory only and distribute it via encapsulateChannelKey(). Any byte sequence (document, metadata blob, message body) can be encrypted as a single call; encrypt metadata and content together in a single plaintext rather than separately."
                    technology "function"
                    tags "Code"
                }
                chrislyons_dev_flarelette_crypto__src__decryptdoc = component "src.decryptDoc" {
                    description "Decrypt a document encrypted by encryptDoc(). Verifies the HMAC-SHA512 MAC in constant time before attempting decryption. Throws immediately on MAC failure — no partial decryption, no timing oracle."
                    technology "function"
                    tags "Code"
                }
                chrislyons_dev_flarelette_crypto__src__generatechannelkeypairs = component "src.generateChannelKeypairs" {
                    description "Generate a hybrid ML-KEM-1024 + X25519 keypair. Both key types are generated with cryptographically random seeds. Returns an opaque ChannelKeypairs handle — internal key bytes are not accessible to application code. Use getPublicKey() to obtain the shareable public portion and wrapKeyBundle() to persist the full keypair."
                    technology "function"
                    tags "Code"
                }
                chrislyons_dev_flarelette_crypto__src__getpublickey = component "src.getPublicKey" {
                    description "Extract the public portion of a keypair for sharing with recipients. The returned ChannelPublicKey is safe to share out-of-band (Signal, QR code, etc.). It contains only public key material — no secret key bytes."
                    technology "function"
                    tags "Code"
                }
                chrislyons_dev_flarelette_crypto__src__hybridencapsulate = component "src.hybridEncapsulate" {
                    technology "function"
                    tags "Code"
                }
                chrislyons_dev_flarelette_crypto__src__hybriddecapsulate = component "src.hybridDecapsulate" {
                    technology "function"
                    tags "Code"
                }
                chrislyons_dev_flarelette_crypto__src__toarraybuffer = component "src.toArrayBuffer" {
                    description "Convert a Uint8Array to a plain ArrayBuffer. Web Crypto requires ArrayBuffer (not ArrayBufferLike) for all key and data parameters. Noble functions return Uint8Array<ArrayBufferLike>, which may be backed by a SharedArrayBuffer. This ensures we always pass a plain ArrayBuffer to satisfy both the DOM types and runtime requirements."
                    technology "function"
                    tags "Code"
                }
                chrislyons_dev_flarelette_crypto__src__importaeskey = component "src.importAesKey" {
                    technology "function"
                    tags "Code"
                }
                chrislyons_dev_flarelette_crypto__src__aesgcmencrypt = component "src.aesGcmEncrypt" {
                    description "AES-256-GCM encrypt. Returns ciphertext with the 16-byte GCM auth tag appended. The caller is responsible for generating a unique 12-byte IV per encryption. Reusing an IV with the same key is catastrophic — this function does not enforce uniqueness; callers must generate IVs via randomIv()."
                    technology "function"
                    tags "Code"
                }
                chrislyons_dev_flarelette_crypto__src__aesgcmdecrypt = component "src.aesGcmDecrypt" {
                    description "AES-256-GCM decrypt. Throws if the GCM auth tag is invalid. This is a secondary authentication check; callers should validate the outer HMAC-SHA512 MAC before calling this."
                    technology "function"
                    tags "Code"
                }
                chrislyons_dev_flarelette_crypto__src__hmacsha512 = component "src.hmacSha512" {
                    description "Compute HMAC-SHA512. Used as the outer MAC in Encrypt-then-MAC. The message should include both the nonce and the ciphertext to prevent nonce-swapping attacks."
                    technology "function"
                    tags "Code"
                }
                chrislyons_dev_flarelette_crypto__src__constanttimeequal = component "src.constantTimeEqual" {
                    description "Constant-time byte equality check. Always use this — not ===, not a manual loop — when comparing MACs or secrets. Timing-safe comparison prevents MAC oracle attacks."
                    technology "function"
                    tags "Code"
                }
                chrislyons_dev_flarelette_crypto__src__randomiv = component "src.randomIv" {
                    description "Generate a cryptographically random 12-byte IV for AES-GCM."
                    technology "function"
                    tags "Code"
                }
                chrislyons_dev_flarelette_crypto__src__concatbytes = component "src.concatBytes" {
                    description "Concatenate Uint8Arrays into a single Uint8Array."
                    technology "function"
                    tags "Code"
                }
                chrislyons_dev_flarelette_crypto__src___getkeypairinternal = component "src._getKeypairInternal" {
                    technology "function"
                    tags "Code"
                }
                chrislyons_dev_flarelette_crypto__src__channelkeypairs = component "src.ChannelKeypairs" {
                    description "An opaque handle wrapping a hybrid ML-KEM-1024 + X25519 keypair. Create via generateChannelKeypairs(). Persist via wrapKeyBundle()/unwrapKeyBundle(). Do not inspect or construct directly — internal layout is not guaranteed."
                    technology "class"
                    tags "Code"
                }
            }

        }
    }

    views {
        systemContext flarelette_crypto "SystemContext" {
            include flarelette_crypto
            autoLayout lr 100 100
        }

        container flarelette_crypto "Containers" {
            include chrislyons_dev_flarelette_crypto
            autoLayout lr 100 100
        }


        component chrislyons_dev_flarelette_crypto "Components__chrislyons_dev_flarelette_crypto" {
            include chrislyons_dev_flarelette_crypto__src
            exclude "element.tag==Code"
            autoLayout lr 100 100
        }


        component chrislyons_dev_flarelette_crypto "Classes_chrislyons_dev_flarelette_crypto__src" {
            include chrislyons_dev_flarelette_crypto__src__generatechannelkey
            include chrislyons_dev_flarelette_crypto__src__encapsulatechannelkey
            include chrislyons_dev_flarelette_crypto__src__decapsulatechannelkey
            include chrislyons_dev_flarelette_crypto__src__derivekey
            include chrislyons_dev_flarelette_crypto__src__encryptdoc
            include chrislyons_dev_flarelette_crypto__src__decryptdoc
            include chrislyons_dev_flarelette_crypto__src__generatechannelkeypairs
            include chrislyons_dev_flarelette_crypto__src__getpublickey
            include chrislyons_dev_flarelette_crypto__src__hybridencapsulate
            include chrislyons_dev_flarelette_crypto__src__hybriddecapsulate
            include chrislyons_dev_flarelette_crypto__src__toarraybuffer
            include chrislyons_dev_flarelette_crypto__src__importaeskey
            include chrislyons_dev_flarelette_crypto__src__aesgcmencrypt
            include chrislyons_dev_flarelette_crypto__src__aesgcmdecrypt
            include chrislyons_dev_flarelette_crypto__src__hmacsha512
            include chrislyons_dev_flarelette_crypto__src__constanttimeequal
            include chrislyons_dev_flarelette_crypto__src__randomiv
            include chrislyons_dev_flarelette_crypto__src__concatbytes
            include chrislyons_dev_flarelette_crypto__src___getkeypairinternal
            include chrislyons_dev_flarelette_crypto__src__channelkeypairs
            autoLayout lr 100 100
        }


/**
 * Default Structurizr theme for Archlette
 * 
 * This theme provides a modern, professional color scheme for architecture diagrams
 * with clear visual hierarchy and accessibility considerations.
 */

theme default

// Element styles
styles {
    // Person/Actor styles
    element "Person" {
        background #08427b
        color #ffffff
        shape Person
        width 200
        height 120
        fontSize 14
    }

    // External System styles
    element "External System" {
        background #999999
        color #ffffff
        shape RoundedBox
        width 240
        height 140
        fontSize 14
    }

    element "External" {
        background #999999
        color #ffffff
        shape RoundedBox
        width 240
        height 140
        fontSize 14
    }

    // System styles
    element "Software System" {
        background #1168bd
        color #ffffff
        shape RoundedBox
        width 280
        height 160
        fontSize 16
    }

    // Container styles
    element "Container" {
        background #438dd5
        color #ffffff
        shape RoundedBox
        width 260
        height 150
        fontSize 14
    }

    element "Database" {
        background #438dd5
        color #ffffff
        shape Cylinder
        width 200
        height 140
        fontSize 14
    }

    element "Web Browser" {
        background #438dd5
        color #ffffff
        shape WebBrowser
        width 240
        height 150
        fontSize 14
    }

    element "Mobile App" {
        background #438dd5
        color #ffffff
        shape MobileDevicePortrait
        width 180
        height 200
        fontSize 14
    }

    // Component styles
    element "Component" {
        background #85bbf0
        color #000000
        shape RoundedBox
        width 220
        height 130
        fontSize 12
    }

    // Code element styles (classes, functions, etc.)
    element "Code" {
        background #d4e8fc
        color #000000
        shape RoundedBox
        width 200
        height 100
        fontSize 11
    }

    // Technology-specific styles
    element "Cloudflare Worker" {
        background #f6821f
        color #ffffff
        shape RoundedBox
        width 220
        height 130
        fontSize 12
    }

    element "Service" {
        background #438dd5
        color #ffffff
        shape RoundedBox
        width 220
        height 130
        fontSize 12
    }

    element "API" {
        background #85bbf0
        color #000000
        shape Hexagon
        width 180
        height 120
        fontSize 12
    }

    element "Queue" {
        background #85bbf0
        color #000000
        shape Pipe
        width 200
        height 100
        fontSize 12
    }

    // Tag-based styles
    element "Internal System" {
        background #1168bd
        color #ffffff
    }

    element "Deprecated" {
        background #cc0000
        color #ffffff
        opacity 60
    }

    element "Future" {
        background #dddddd
        color #000000
        opacity 50
        stroke #999999
        strokeWidth 2
    }

    element "Auto Generated" {
        stroke #999999
        strokeWidth 1
    }

    // Infrastructure styles
    element "Infrastructure" {
        background #92278f
        color #ffffff
        shape RoundedBox
        width 220
        height 130
        fontSize 12
    }

    element "Message Bus" {
        background #85bbf0
        color #000000
        shape Pipe
        width 200
        height 100
        fontSize 12
    }

    // Relationship styles
    relationship "Relationship" {
        color #707070
        dashed false
        routing Curved
        fontSize 12
        thickness 2
    }

    relationship "Async" {
        dashed true
        color #707070
    }

    relationship "Sync" {
        dashed false
        color #707070
    }

    relationship "Uses" {
        color #707070
        dashed false
    }

    relationship "Depends On" {
        color #707070
        dashed true
    }
}

// Diagram customization
branding {
    font "Arial"
}

    }

}
