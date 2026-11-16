import Foundation

public enum DiagnosticLayer: String, Sendable, CaseIterable {
    case platform
    case catalog
    case profile
    case channel
    case transport
    case lifecycle
}

public enum DiagnosticEventCode: String, Sendable, CaseIterable {
    case processStarted
    case processStopped
    case cardInserted
    case cardRemoved
    case connectionCreated
    case connectionInvalidated
    case profileRecognized
    case publicationCompleted
    case operationStarted
    case operationCompleted
    case operationRejected
    case authorizationStarted
    case authorizationCompleted
    case recoveryStarted
    case recoveryCompleted

    // A code names an event at its owning layer. Generic operation events are
    // shared by the lifecycle, channel, and transport contracts. Other codes
    // are narrower so a mislabeled event fails closed.
    fileprivate func belongs(to layer: DiagnosticLayer) -> Bool {
        switch self {
        case .processStarted, .processStopped, .cardInserted, .cardRemoved,
             .authorizationStarted, .authorizationCompleted,
             .recoveryStarted, .recoveryCompleted:
            layer == .lifecycle
        case .connectionCreated, .connectionInvalidated:
            layer == .transport
        case .profileRecognized:
            layer == .profile
        case .publicationCompleted:
            layer == .catalog
        case .operationStarted, .operationCompleted, .operationRejected:
            layer == .lifecycle || layer == .channel || layer == .transport
        }
    }
}

public enum DiagnosticErrorCategory: String, Sendable, CaseIterable {
    case unsupported
    case invalidState
    case communication
    case canceled
    case corruptedData
    case authenticationFailed
}

public enum ForbiddenDiagnosticValueClass: String, Sendable, CaseIterable {
    case pin
    case rawAPDU
    case chipSerial
    case ckaID
    case certificateBytes
    case certificateHolderMetadata
    case signingInput
    case sessionKey
    case terminalPrivateMaterial
}

public enum DiagnosticAttributeCandidate: Sendable, Equatable {
    case profileVersion(ProfileVersion)
    case durationMilliseconds(UInt64)
    case count(UInt64)
    case errorCategory(DiagnosticErrorCategory)
    case forbidden(ForbiddenDiagnosticValueClass)
}

public enum DiagnosticAttribute: Sendable, Equatable {
    case profileVersion(ProfileVersion)
    case durationMilliseconds(UInt64)
    case count(UInt64)
    case errorCategory(DiagnosticErrorCategory)
}

public struct DiagnosticEventCandidate: Sendable {
    public let timestamp: Date
    public let correlationID: CorrelationID
    public let layer: DiagnosticLayer
    public let code: DiagnosticEventCode
    public let attributes: [DiagnosticAttributeCandidate]

    public init(
        timestamp: Date = Date(),
        correlationID: CorrelationID,
        layer: DiagnosticLayer,
        code: DiagnosticEventCode,
        attributes: [DiagnosticAttributeCandidate] = []
    ) {
        self.timestamp = timestamp
        self.correlationID = correlationID
        self.layer = layer
        self.code = code
        self.attributes = attributes
    }
}

public struct DiagnosticEvent: Sendable, Equatable {
    public let timestamp: Date
    public let correlationID: CorrelationID
    public let layer: DiagnosticLayer
    public let code: DiagnosticEventCode
    public let attributes: [DiagnosticAttribute]
}

public struct MonotonicDiagnosticTimer: Sendable {
    private let startedAtUptimeNanoseconds: UInt64

    public init(
        startedAtUptimeNanoseconds: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) {
        self.startedAtUptimeNanoseconds = startedAtUptimeNanoseconds
    }

    public func durationAttribute(
        endingAtUptimeNanoseconds: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) -> DiagnosticAttributeCandidate {
        let elapsed = endingAtUptimeNanoseconds >= startedAtUptimeNanoseconds
            ? endingAtUptimeNanoseconds - startedAtUptimeNanoseconds
            : 0
        return .durationMilliseconds(elapsed / 1_000_000)
    }
}

public enum DiagnosticPrivacyRejection: Error, Sendable, Equatable {
    case forbidden(ForbiddenDiagnosticValueClass)
    case invalidProfileVersion
    case unrelatedLayer(code: DiagnosticEventCode, layer: DiagnosticLayer)
}

public enum DiagnosticPrivacyFilter {
    public static func review(_ candidate: DiagnosticEventCandidate) throws -> DiagnosticEvent {
        // Reject forbidden data anywhere in the candidate before validating other
        // attributes. The rejection never carries the original attribute value.
        for attribute in candidate.attributes {
            if case let .forbidden(valueClass) = attribute {
                throw DiagnosticPrivacyRejection.forbidden(valueClass)
            }
        }
        let reviewed: [DiagnosticAttribute] = try candidate.attributes.map { attribute in
            switch attribute {
            case let .profileVersion(value):
                guard isPublicVersion(value.rawValue) else {
                    throw DiagnosticPrivacyRejection.invalidProfileVersion
                }
                return .profileVersion(value)
            case let .durationMilliseconds(value):
                return .durationMilliseconds(value)
            case let .count(value):
                return .count(value)
            case let .errorCategory(value):
                return .errorCategory(value)
            case let .forbidden(valueClass):
                throw DiagnosticPrivacyRejection.forbidden(valueClass)
            }
        }
        guard candidate.code.belongs(to: candidate.layer) else {
            throw DiagnosticPrivacyRejection.unrelatedLayer(
                code: candidate.code,
                layer: candidate.layer
            )
        }
        return DiagnosticEvent(
            timestamp: candidate.timestamp,
            correlationID: candidate.correlationID,
            layer: candidate.layer,
            code: candidate.code,
            attributes: reviewed
        )
    }

    // One to three decimal components, each one to nine ASCII digits. This
    // accepts the current "1" and "1.0.0" profile constants while bounding
    // diagnostic length and excluding arbitrary text and control characters.
    private static func isPublicVersion(_ rawValue: String) -> Bool {
        let bytes = rawValue.utf8
        guard !bytes.isEmpty, bytes.count <= 29 else { return false }

        var components = 1
        var digits = 0
        for byte in bytes {
            if byte == 46 { // ASCII period
                guard digits > 0, components < 3 else { return false }
                components += 1
                digits = 0
            } else {
                guard byte >= 48, byte <= 57, digits < 9 else { return false }
                digits += 1
            }
        }
        return digits > 0
    }
}
