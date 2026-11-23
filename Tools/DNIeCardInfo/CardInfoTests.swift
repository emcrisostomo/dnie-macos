import Foundation
import Security

@main
enum CardInfoTests {
    private static let readerCanary = "synthetic reader name\nserial=PRIVATE_READER"
    private static let tokenCanary = "synthetic token value\nidentifier=PRIVATE_TOKEN"

    private static func snapshot(_ slots: [SlotObservation],
                                 changed: Bool = false) -> InventorySnapshot {
        let names = slots.indices.map { "\(readerCanary)-\($0)" }
        return InventorySnapshot(initialNames: names, slots: slots,
                                 finalNames: changed ? names + ["new reader"] : Array(names.reversed()))
    }

    private static func check(
        _ inventory: InventorySnapshot,
        card: String,
        readers: String,
        cards: String,
        publication: String = "not_checked",
        authentication: String = "not_checked",
        signature: String = "not_checked",
        exitCode: Int32 = 0,
        authenticationQuery: RoleQuery? = nil,
        signatureQuery: RoleQuery? = nil
    ) {
        var queried: [DNIeRole] = []
        let report = CardInfoReport.observe(inventory) { role in
            queried.append(role)
            switch role {
            case .authentication:
                guard let authenticationQuery else { fatalError("unexpected Authentication query") }
                return authenticationQuery
            case .signature:
                guard let signatureQuery else { fatalError("unexpected Signature query") }
                return signatureQuery
            }
        }
        precondition(report.lines == [
            "reader_count=\(readers)", "valid_card_count=\(cards)", "card=\(card)",
            "dnie_publication=\(publication)", "authentication=\(authentication)",
            "signature=\(signature)",
        ], "unexpected categorical report")
        precondition(report.exitCode == exitCode, "unexpected exit code")
        precondition(queried == (authenticationQuery == nil ? [] : [.authentication, .signature]),
                     "unexpected query order or count")
    }

    private static func checkQueryShape() {
        for (role, label) in [
            (DNIeRole.authentication, "Spanish DNIe Authentication Key"),
            (.signature, "Spanish DNIe Signature Key"),
        ] {
            let query = CardInfo.roleKeyQuery(role)
            precondition(query.count == 7, "unexpected Security query keys")
            precondition(query[kSecUseDataProtectionKeychain] as? Bool == true)
            precondition(query[kSecUseAuthenticationUI] as? String == kSecUseAuthenticationUIFail as String)
            precondition(query[kSecMatchLimit] as? NSNumber == NSNumber(value: 65))
            precondition(query[kSecClass] as? String == kSecClassKey as String)
            precondition(query[kSecAttrKeyClass] as? String == kSecAttrKeyClassPrivate as String)
            precondition(query[kSecAttrLabel] as? String == label)
            precondition(query[kSecReturnRef] as? Bool == true)
        }
    }

    private static func checkNativeBounds() {
        let upperBound = Array(repeating: "non-key fixture", count: 64) as CFArray
        let overflow = Array(repeating: "non-key fixture", count: 65) as CFArray
        precondition(CardInfo.boundedNativeArray(nil) == nil)
        precondition(CardInfo.boundedNativeArray("invalid result" as CFString) == nil)
        precondition(CardInfo.boundedNativeArray([] as CFArray) == nil)
        precondition(CardInfo.boundedNativeArray(overflow) == nil)
        precondition(CardInfo.boundedNativeArray(upperBound).map(CFArrayGetCount) == 64)
        precondition(CardInfo.boundedKeyReferences(upperBound) == nil)
    }

    static func main() {
        checkQueryShape()
        checkNativeBounds()
        check(.unavailable, card: "inventory_unavailable", readers: "unknown",
              cards: "unknown", exitCode: 1)
        check(snapshot([]), card: "no_reader", readers: "0", cards: "0")
        check(snapshot([.empty]), card: "empty", readers: "1", cards: "0")
        check(snapshot([.empty, .mute]), card: "unresponsive_or_unknown", readers: "2", cards: "0")
        check(snapshot([.probing, .empty]), card: "probing", readers: "2", cards: "0")
        check(snapshot([.unresolved, .valid]), card: "inventory_unavailable", readers: "2",
              cards: "unknown", exitCode: 1)
        check(snapshot([.unknown]), card: "inventory_unavailable", readers: "1",
              cards: "unknown", exitCode: 1)
        check(snapshot([.missing]), card: "inventory_changed", readers: "unknown",
              cards: "unknown", exitCode: 1)
        check(snapshot([.valid], changed: true), card: "inventory_changed", readers: "unknown",
              cards: "unknown", exitCode: 1)
        check(snapshot([.valid]), card: "responsive", readers: "1", cards: "1",
              publication: "not_observed", authentication: "not_observed", signature: "not_observed",
              authenticationQuery: .itemNotFound, signatureQuery: .success([.nonToken]))
        check(snapshot([.empty, .valid, .valid]), card: "responsive", readers: "3", cards: "2",
              publication: "observed", authentication: "visible", signature: "visible",
              authenticationQuery: .success([.nonToken, .token(tokenCanary)]),
              signatureQuery: .success([.token("another private identifier")]))
        check(snapshot([.valid]), card: "responsive", readers: "1", cards: "1",
              publication: "observed", authentication: "visible", signature: "not_observed",
              authenticationQuery: .success([.token(tokenCanary)]), signatureQuery: .itemNotFound)
        check(snapshot([.valid]), card: "responsive", readers: "1", cards: "1",
              publication: "indeterminate", authentication: "indeterminate", signature: "visible",
              exitCode: 1, authenticationQuery: .interactionBlocked,
              signatureQuery: .success([.token(tokenCanary)]))
        check(snapshot([.valid]), card: "responsive", readers: "1", cards: "1",
              publication: "indeterminate", authentication: "indeterminate", signature: "indeterminate",
              exitCode: 1, authenticationQuery: .failure,
              signatureQuery: .success([.token(""), .token(tokenCanary)]))
        check(snapshot([.valid]), card: "responsive", readers: "1", cards: "1",
              publication: "indeterminate", authentication: "indeterminate", signature: "indeterminate",
              exitCode: 1, authenticationQuery: .success([.malformed]),
              signatureQuery: .success(Array(repeating: .token(tokenCanary), count: 65)))
        print("card_info_snapshot_tests=pass")
    }
}
