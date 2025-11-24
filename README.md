# twoway: Encrypted request-response messaging using HPKE.

`twoway` is a Go package that provides encrypted request-response messaging using HPKE.

[![Go Reference](https://pkg.go.dev/badge/github.com/openpcc/twoway.svg)](https://pkg.go.dev/github.com/openpcc/twoway)

## Overview

`twoway` allows a sender to send a request message to one (or more) receivers, and for those receiver(s) to send back a response message. Twoway then guarantees the integrity of this roundtrip by cryptographically tying the response message to the request message.

HPKE sealed messages always flow in one direction: `sender->receiver`. HPKE guarantees that only the intended receiver can decrypt the message.

`twoway` adds a return leg to this flow. It models a flow in two directions, `sender->receiver->sender` if you will. `twoway` guarantees that:
- The request message can only be decrypted by the intended receiver.
- The response message can only have been sent by the intended receiver.
- The response message was in response to the request message.

## Features
- One-to-one and one-to-many messaging.
- Chunked and non-chunked messages, both using the `io.Reader` interface.
- One-to-one messaging is fully compatible with the [OHTTP](https://www.rfc-editor.org/rfc/rfc9458.html) and [Chunked OHTTP](https://www.ietf.org/archive/id/draft-ietf-ohai-chunked-ohttp-03.html).
- For power users: Allows for injection of custom HPKE components to support hardware integration.
- Build on top of the primitives provided by [`cloudflare/circl`](https://github.com/cloudflare/circl).

## Walkthrough

In this example a sender sends a regular request to a receiver. Let's assume we have a `hpke.Suite` and keys set up.

First, we need to create a sender. In the context of HTTP apps, these will often be created on the client.

```go
// the sender sends a regular request
sender, err := twoway.NewRequestSender(suite, keyID, receiverPubKey, rand.Reader)
if err != nil {
	// handle error
}
```

This sender then creates a request sealer to seal our secret message.

This request sealer also needs a media type, this media type needs to match when decrypting the
request. Baking the media type into the encrypted message makes it a lot less likely that someone
can trick the receiver into interpreting this message in the wrong way.

You're free to choose any media type you want.

```go
reqSealer, err := sender.NewRequestSealer(bytes.NewReader("a secret message"), []byte("secret-req"))
if err != nil {
	// handle error.
}
```

The `reqSealer` is an `io.Reader`, you can read from it to get your encrypted message.

```go
reqCiphertext, err := io.ReadAll(reqSealer)
if err != nil {
	// handle error
}
```

A receiver is created as follows. Again, when dealing with HTTP apps these will often be created on the server.

```go
reqReceiver, err := twoway.NewRequestReceiver(suite, keyID, receiverPrivateKey, rand.Reader)
if err != nil {
	// handle error.
}
```

This receiver can now create an opener to open our earlier `reqCiphertext`. The media type
needs to match our earlier media type.

```go
reqOpener, err := reqReceiver.NewRequestOpener(bytes.NewReader(reqCiphertext), []byte("secret-req"))
if err != nil {
	// handle error
}
```

Again, the `reqOpener` is an `io.Reader` so we can read from it to get the plaintext.

```go
reqPlaintext, err := io.ReadAll(reqOpener)
if err != nil {
	// handle error
}

// reqPlaintext now contains []byte("a secret message")
```

With the request handled, let's write back a response in chunks.

### A chunked response.

Let's say we have an `io.Reader` called `source` that reads data from some kind of stream.

The `reqOpener` allows you to create a response sealer, but by default it will write a non-chunked response.
We need to enable chunking by providing it with the `twoway.EnableChunking` option.

```go
respSealer, err := reqOpener.NewResponseSealer(
	source, []byte("secret-chunked-resp"), twoway.EnableChunking(),
)
if err != nil {
	// handle error
}
```

You can now read ciphertext chunks from `respSealer`.

Back on the sending side, we can pass these chunks (or this reader directly) to a response opener. This can be created
via `reqSealer` we created earlier. We again need to match the media type, but also need to enable chunking.

```go
respOpener, err := reqSealer.NewResponseOpener(
	respSealer, []byte("secret-chunked-resp")), twoway.EnableChunking(),
)
if err != nil {
	// handle error
}
```

By reading from the `respOpener` you will now get the plaintext response in chunks.

## One-to-many messaging

One-to-many messaging works similar to one-to-one messaging.

The differences are as follows:
- Create sender and receiver using `NewMultiRequestSender` and `NewMultiRequestReceiver`.
- Create a request sealer as normal.
- Call `EncapsulateKey` on the request sealer for each receiver.
- Provide the resulting encapsulated key to each receiver together with the ciphertext.
- The response flow is the same as in one-to-one messaging.

## Found a security issue?

Reach out to [security@confidentsecurity.com](mailto:security@confidentsecurity.com).

## Thread Safety

The package makes no guarantees about thread safety. Concurrent access should be externally synchronized.

## Development

Run tests with `go test ./...`

## Other Work

[`cloudflare/circl`](https://github.com/cloudflare/circl), and [tink](https://developers.google.com/tink) both provide HPKE implementations in go but neither support streaming bidirectional messages.
