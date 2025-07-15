# Double Edged Private Key Encryption (DEKPE)

## Abstract
[Todo]

## Concept
Hash(M, prA, pubB) == Hash(M, prB, pubA)
This is similar to Diffie-Hellman but also bidirectional

### Usage
```rs
cargo run
```

## Output
msg = Hello world
plain_text = Hello world 

Plain text is after decryption
Sender can still decrypt with his generated shared key hence it's bidirectional.
