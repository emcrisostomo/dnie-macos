import CryptoTokenKit
import Darwin
import Foundation
import LocalAuthentication
import Security

#if !CARD_INFO_TESTING
@main
#endif
enum CardInfo {
    static func main() {
        guard CommandLine.arguments.count == 1 else {
            exit(64)
        }
        let report = observe()
        print(report.lines.joined(separator: "\n"))
        exit(report.exitCode)
    }

    private static func observe() -> CardInfoReport {
        CardInfoReport.observe(snapshot(), readRole: readRole)
    }

    private static func snapshot() -> InventorySnapshot {
        guard let manager = TKSmartCardSlotManager.default else {
            return .unavailable
        }
        let names = manager.slotNames
        guard names.count <= InventorySnapshot.maximumSlots else {
            return .unavailable
        }
        let slots = names.map { name -> SlotObservation in
            guard let slot = manager.slotNamed(name) else { return .unresolved }
            switch slot.state {
            case .missing: return .missing
            case .empty: return .empty
            case .probing: return .probing
            case .muteCard: return .mute
            case .validCard: return .valid
            @unknown default: return .unknown
            }
        }
        return InventorySnapshot(initialNames: names, slots: slots, finalNames: manager.slotNames)
    }

    static func roleKeyQuery(_ role: DNIeRole) -> [CFString: Any] {
        // Match the generic role labels emitted by PlatformItemMapper.
        let label = switch role {
        case .authentication: "Spanish DNIe Authentication Key"
        case .signature: "Spanish DNIe Signature Key"
        }
        return [
            kSecClass: kSecClassKey,
            kSecAttrLabel: label,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            // A sentinel result distinguishes a full acceptable batch from overflow.
            kSecMatchLimit: NSNumber(value: RoleQuery.maximumReferences + 1),
            kSecUseDataProtectionKeychain: true,
            kSecReturnRef: true,
            // Retain the explicit fail option used in the target validation.
            kSecUseAuthenticationUI: kSecUseAuthenticationUIFail,
        ]
    }

    static func boundedNativeArray(_ result: CFTypeRef?) -> CFArray? {
        guard let result, CFGetTypeID(result) == CFArrayGetTypeID() else { return nil }
        // The native type check validates the pointer before using CFArray APIs.
        let array = Unmanaged<CFArray>.fromOpaque(
            Unmanaged.passUnretained(result).toOpaque()
        ).takeUnretainedValue()
        let count = CFArrayGetCount(array)
        return (1...RoleQuery.maximumReferences).contains(count) ? array : nil
    }

    static func boundedKeyReferences(_ result: CFTypeRef?) -> [SecKey]? {
        guard let array = boundedNativeArray(result),
              let references = array as? [SecKey],
              references.allSatisfy({ CFGetTypeID($0) == SecKeyGetTypeID() }) else {
            return nil
        }
        return references
    }

    private static func readRole(_ role: DNIeRole) -> RoleQuery {
        let context = LAContext()
        defer { context.invalidate() }
        context.interactionNotAllowed = true
        guard context.interactionNotAllowed else { return .failure }
        var query = roleKeyQuery(role)
        query[kSecUseAuthenticationContext] = context
        var result: CFTypeRef?
        switch SecItemCopyMatching(query as CFDictionary, &result) {
        case errSecItemNotFound: return .itemNotFound
        case errSecInteractionNotAllowed: return .interactionBlocked
        case errSecSuccess: break
        default: return .failure
        }
        guard let references = boundedKeyReferences(result) else { return .failure }
        return .success(references.map { reference in
            guard let attributes = SecKeyCopyAttributes(reference) as? [CFString: Any] else {
                return .malformed
            }
            guard let token = attributes[kSecAttrTokenID] else { return .nonToken }
            guard let identifier = token as? String else { return .malformed }
            return .token(identifier)
        })
    }
}
