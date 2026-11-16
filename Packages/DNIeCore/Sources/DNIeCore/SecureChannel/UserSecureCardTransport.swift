/// A card transport whose requests and responses are protected by a verified
/// DNIe user-role secure channel.
///
/// The marker prevents private operations from accepting a plain card
/// transport. The concrete stateful adapter is built by the secure-channel
/// establishment boundary.
public protocol UserSecureCardTransport: CardTransport {}
