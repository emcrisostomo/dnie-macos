enum SlotObservation {
    case missing, empty, probing, mute, valid, unresolved, unknown
}

enum InventorySnapshot {
    static let maximumSlots = 64

    case unavailable
    case observed(initialNames: [String], slots: [SlotObservation], finalNames: [String])

    init(initialNames: [String], slots: [SlotObservation], finalNames: [String]) {
        self = .observed(initialNames: initialNames, slots: slots, finalNames: finalNames)
    }
}

enum DNIeRole {
    case authentication, signature
}

enum RoleReference {
    case nonToken
    case token(String)
    case malformed
}

enum RoleQuery {
    static let maximumReferences = 64

    case success([RoleReference])
    case itemNotFound, interactionBlocked, failure
}

struct CardInfoReport {
    private enum CardState: String {
        case noReader = "no_reader"
        case empty, probing
        case unresponsiveOrUnknown = "unresponsive_or_unknown"
        case responsive
        case inventoryUnavailable = "inventory_unavailable"
        case inventoryChanged = "inventory_changed"
    }

    private enum RoleVisibility: String {
        case notChecked = "not_checked"
        case visible
        case notObserved = "not_observed"
        case indeterminate

        init(_ query: RoleQuery) {
            switch query {
            case .itemNotFound:
                self = .notObserved
            case .interactionBlocked, .failure:
                self = .indeterminate
            case .success(let references):
                guard !references.isEmpty, references.count <= RoleQuery.maximumReferences else {
                    self = .indeterminate
                    return
                }
                var foundToken = false
                for reference in references {
                    switch reference {
                    case .nonToken:
                        continue
                    case .token(let identifier) where !identifier.isEmpty:
                        foundToken = true
                    case .token, .malformed:
                        self = .indeterminate
                        return
                    }
                }
                self = foundToken ? .visible : .notObserved
            }
        }
    }

    private let readerCount: Int?
    private let validCardCount: Int?
    private let card: CardState
    private var authentication: RoleVisibility = .notChecked
    private var signature: RoleVisibility = .notChecked

    private var publication: String {
        if authentication == .notChecked && signature == .notChecked { return "not_checked" }
        if authentication == .indeterminate || signature == .indeterminate { return "indeterminate" }
        if authentication == .visible || signature == .visible { return "observed" }
        return "not_observed"
    }

    var lines: [String] {
        [
            "reader_count=\(readerCount.map(String.init) ?? "unknown")",
            "valid_card_count=\(validCardCount.map(String.init) ?? "unknown")",
            "card=\(card.rawValue)",
            "dnie_publication=\(publication)",
            "authentication=\(authentication.rawValue)",
            "signature=\(signature.rawValue)",
        ]
    }

    var exitCode: Int32 {
        if card == .inventoryUnavailable || card == .inventoryChanged
            || authentication == .indeterminate || signature == .indeterminate {
            return 1
        }
        return 0
    }

    static func observe(
        _ snapshot: InventorySnapshot,
        readRole: (DNIeRole) -> RoleQuery
    ) -> CardInfoReport {
        var report = reportForInventory(snapshot)
        if report.card == .responsive {
            report.authentication = RoleVisibility(readRole(.authentication))
            report.signature = RoleVisibility(readRole(.signature))
        }
        return report
    }

    private static func reportForInventory(_ snapshot: InventorySnapshot) -> CardInfoReport {
        guard case .observed(let initialNames, let slots, let finalNames) = snapshot,
              initialNames.count <= InventorySnapshot.maximumSlots,
              slots.count == initialNames.count,
              Set(initialNames).count == initialNames.count else {
            return CardInfoReport(readerCount: nil, validCardCount: nil, card: .inventoryUnavailable)
        }
        guard finalNames.count == initialNames.count,
              Set(finalNames) == Set(initialNames),
              !slots.contains(.missing) else {
            return CardInfoReport(readerCount: nil, validCardCount: nil, card: .inventoryChanged)
        }

        let readers = slots.count
        if slots.contains(.unresolved) || slots.contains(.unknown) {
            return CardInfoReport(readerCount: readers, validCardCount: nil, card: .inventoryUnavailable)
        }

        let valid = slots.count { $0 == .valid }
        let card: CardState
        if readers == 0 {
            card = .noReader
        } else if valid > 0 {
            card = .responsive
        } else if slots.contains(.probing) {
            card = .probing
        } else if slots.contains(.mute) {
            card = .unresponsiveOrUnknown
        } else {
            card = .empty
        }
        return CardInfoReport(readerCount: readers, validCardCount: valid, card: card)
    }
}
