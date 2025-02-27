REBOL [
    title:  "Password-Based Key Derivation Function 2"
    author: @Oldes
    needs:   3.11.0
    version: 1.0.0
    exports: [pbkdf2]
]

pbkdf2: function [
    pass   [any-string! binary!] "Password"
    salt   [any-string! binary!] "Salt value"
    count  [integer!] "Number of iterations"
    length [integer!] "Requested length of the result (key) in bytes"
    method [word!]    "Checksum method to be used [sha1 sha256...]"
][
    ;; Convert input password and salt to binary format
    pass: to binary! pass
    salt: to binary! salt
    ;; Initialize output buffer for the derived key
    output: make binary! length
    ;; Initialize last block with the salt
    last: copy salt
    ;; Determine the length of the hash output for the selected method
    hash-len: select [sha1 20 sha224 28 sha256 32 sha384 48 sha512 64] :method
    ;; Calculate the number of hash blocks needed to meet the requested length
    block-cnt: round/ceiling (length / hash-len)

    repeat i block-cnt [
        ;; Write the salt and block index (as big-endian 32-bit) into last
        binary/write last [BYTES :salt UI32BE :i]
        ;; Compute the first hash value (U1) using the password
        last: xorsum: checksum/with last method pass
        ;; Perform additional iterations (U2, U3, ..., Ucount)
        repeat j (count - 1) [
            ;; Compute the next hash in the chain and XOR it with previous results
            xorsum: xorsum xor (last: checksum/with last method pass)
        ]
        ;; Append the derived key fragment to the output buffer
        append output xorsum
    ]
    ;; Crop the output to match the exact requested key length
    copy/part output length
]