REBOL [
    title:  "SCRAM Authentication Exchange"
    author: @Oldes
    needs:   3.11.0
    version: 1.0.0
    exports: [scram]
    notes: [
        https://www.improving.com/thoughts/making-sense-of-scram-sha-256-authentication-in-mongodb/
        https://datatracker.ietf.org/doc/html/rfc5802
    ]
    usage: [
        ;- SCRAM Authentication Exchange Test                      
        ;; https://datatracker.ietf.org/doc/html/rfc5802#section-5
        state: context [
            ;; input values...
            password: "pencil"
            salt: debase "QSXCR+Q6sek8bf92" 64
            iterations: 4096
            method: 'sha1
            gs2-header: "n,," ;;<-- "biws" as base64 (used in the client-final-message-without-proof)
            client-first-message-bare: "n=user,r=fyko+d2lbbFgONRv9qkxdawL"
            server-first-message:      "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096"
            client-final-message-without-proof: "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j"
            ;; output values...
            SaltedPassword:
            ClientKey:
            ServerKey:
            StoredKey:
            AuthMessage:
            ClientSignature:
            ServerSignature:
            ClientProof: none
        ]

        ;; Compute output values using SCRAM and input values in the state object
        scram :state
        ;; Display all values in the state object...
        ? state
        print ["ClientProof:" state/ClientProof]
        print ["   Expected:" debase "v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=" 64]
        print ["ServerProof:" state/ServerSignature]
        print ["   Expected:" debase "rmF9pqV8S7suAoZWja4dJRkFsKQ=" 64]
    ]
]

scram: func [
    "SCRAM Authentication Exchange"
    state [object!] "Populated context with input/output values"
    /local hash-len
][
    with state [
        hash-len: select [sha1 20 sha224 28 sha256 32 sha384 48 sha512 64] :method
        SaltedPassword: make binary! hash-len
        hash: join salt #{00000001}
        hash: SaltedPassword: checksum/with hash :method :password
        loop iterations - 1 [
            SaltedPassword: SaltedPassword xor (hash: checksum/with hash :method :password)
        ]
        ClientKey: checksum/with "Client Key" :method :SaltedPassword
        ServerKey: checksum/with "Server Key" :method :SaltedPassword
        StoredKey: checksum :ClientKey :method

        AuthMessage: rejoin [
            client-first-message-bare #","
            server-first-message #","
            client-final-message-without-proof
        ]
        ClientSignature: checksum/with :AuthMessage :method :StoredKey
        ServerSignature: checksum/with :AuthMessage :method :ServerKey
        ClientProof: ClientSignature xor ClientKey
    ]
]
