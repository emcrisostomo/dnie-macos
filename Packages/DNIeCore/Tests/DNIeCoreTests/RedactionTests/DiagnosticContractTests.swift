import DNIeCore
import Foundation
import XCTest

final class DiagnosticContractTests: XCTestCase {
    func testReviewedEventsShareOperationCorrelationAndKeepClosedMetadata() throws {
        let correlationID = CorrelationID()
        let timestamp = Date(timeIntervalSince1970: 1_700_000_000)
        let started = try DiagnosticPrivacyFilter.review(DiagnosticEventCandidate(
            timestamp: timestamp,
            correlationID: correlationID,
            layer: .lifecycle,
            code: .authorizationStarted
        ))
        let completed = try DiagnosticPrivacyFilter.review(DiagnosticEventCandidate(
            timestamp: timestamp,
            correlationID: correlationID,
            layer: .lifecycle,
            code: .authorizationCompleted,
            attributes: [
                .profileVersion(ProfileVersion("1.0.0")),
                .durationMilliseconds(17),
                .errorCategory(.authenticationFailed),
            ]
        ))
        let unrelated = try DiagnosticPrivacyFilter.review(DiagnosticEventCandidate(
            timestamp: timestamp,
            correlationID: CorrelationID(),
            layer: .lifecycle,
            code: .authorizationStarted
        ))

        XCTAssertEqual(started.timestamp, timestamp)
        XCTAssertEqual(started.correlationID, correlationID)
        XCTAssertEqual(started.layer, .lifecycle)
        XCTAssertEqual(started.code, .authorizationStarted)
        XCTAssertEqual(completed.timestamp, timestamp)
        XCTAssertEqual(completed.correlationID, started.correlationID)
        XCTAssertEqual(completed.layer, .lifecycle)
        XCTAssertEqual(completed.code, .authorizationCompleted)
        XCTAssertEqual(completed.attributes, [
            .profileVersion(ProfileVersion("1.0.0")),
            .durationMilliseconds(17),
            .errorCategory(.authenticationFailed),
        ])
        XCTAssertNotEqual(unrelated.correlationID, started.correlationID)
    }

    func testEventAndErrorRegistriesHaveOnlyReviewedCodes() {
        XCTAssertEqual(Set(DiagnosticLayer.allCases.map(\.rawValue)), [
            "platform", "catalog", "profile", "channel", "transport", "lifecycle",
        ])
        XCTAssertEqual(Set(DiagnosticEventCode.allCases.map(\.rawValue)), [
            "processStarted", "processStopped", "cardInserted", "cardRemoved",
            "connectionCreated", "connectionInvalidated", "profileRecognized",
            "publicationCompleted", "operationStarted", "operationCompleted",
            "operationRejected", "authorizationStarted", "authorizationCompleted",
            "recoveryStarted", "recoveryCompleted",
        ])
        XCTAssertEqual(Set(DiagnosticErrorCategory.allCases.map(\.rawValue)), [
            "unsupported", "invalidState", "communication", "canceled",
            "corruptedData", "authenticationFailed",
        ])
    }

    func testForbiddenAttributeRejectsWholeEventEvenWhenSafeAttributesPrecedeIt() {
        for valueClass in ForbiddenDiagnosticValueClass.allCases {
            let candidate = DiagnosticEventCandidate(
                correlationID: CorrelationID(),
                layer: .channel,
                code: .operationRejected,
                attributes: [
                    .durationMilliseconds(5),
                    .errorCategory(.authenticationFailed),
                    .forbidden(valueClass),
                ]
            )

            XCTAssertThrowsError(try DiagnosticPrivacyFilter.review(candidate)) { error in
                XCTAssertEqual(error as? DiagnosticPrivacyRejection, .forbidden(valueClass))
            }
        }
    }

    func testEventCodeCannotBeAttributedToUnrelatedLayer() {
        let candidate = DiagnosticEventCandidate(
            correlationID: CorrelationID(),
            layer: .transport,
            code: .profileRecognized
        )

        XCTAssertThrowsError(try DiagnosticPrivacyFilter.review(candidate)) { error in
            XCTAssertEqual(
                error as? DiagnosticPrivacyRejection,
                .unrelatedLayer(code: .profileRecognized, layer: .transport)
            )
        }
    }

    func testEveryRegisteredCodeHasOnlyReviewedOwningLayers() throws {
        let ownership: [DiagnosticEventCode: Set<DiagnosticLayer>] = [
            .processStarted: [.lifecycle],
            .processStopped: [.lifecycle],
            .cardInserted: [.lifecycle],
            .cardRemoved: [.lifecycle],
            .connectionCreated: [.transport],
            .connectionInvalidated: [.transport],
            .profileRecognized: [.profile],
            .publicationCompleted: [.catalog],
            .operationStarted: [.lifecycle, .channel, .transport],
            .operationCompleted: [.lifecycle, .channel, .transport],
            .operationRejected: [.lifecycle, .channel, .transport],
            .authorizationStarted: [.lifecycle],
            .authorizationCompleted: [.lifecycle],
            .recoveryStarted: [.lifecycle],
            .recoveryCompleted: [.lifecycle],
        ]
        XCTAssertEqual(Set(ownership.keys), Set(DiagnosticEventCode.allCases))

        for code in DiagnosticEventCode.allCases {
            for layer in DiagnosticLayer.allCases {
                let candidate = DiagnosticEventCandidate(
                    correlationID: CorrelationID(),
                    layer: layer,
                    code: code
                )
                if ownership[code]!.contains(layer) {
                    let event = try DiagnosticPrivacyFilter.review(candidate)
                    XCTAssertEqual(event.code, code)
                    XCTAssertEqual(event.layer, layer)
                } else {
                    XCTAssertThrowsError(try DiagnosticPrivacyFilter.review(candidate)) { error in
                        XCTAssertEqual(
                            error as? DiagnosticPrivacyRejection,
                            .unrelatedLayer(code: code, layer: layer)
                        )
                    }
                }
            }
        }
    }

    func testForbiddenValueRejectsWholeEventBeforeLayerValidation() {
        let candidate = DiagnosticEventCandidate(
            correlationID: CorrelationID(),
            layer: .transport,
            code: .profileRecognized,
            attributes: [.durationMilliseconds(2), .forbidden(.pin)]
        )

        XCTAssertThrowsError(try DiagnosticPrivacyFilter.review(candidate)) { error in
            XCTAssertEqual(error as? DiagnosticPrivacyRejection, .forbidden(.pin))
        }
    }

    func testPublicNumericProfileVersionsAreAccepted() throws {
        for version in ["1", "1.0.0", "123456789.123456789.123456789"] {
            let value = ProfileVersion(version)
            let event = try DiagnosticPrivacyFilter.review(DiagnosticEventCandidate(
                correlationID: CorrelationID(),
                layer: .profile,
                code: .profileRecognized,
                attributes: [.profileVersion(value)]
            ))
            XCTAssertEqual(event.attributes, [.profileVersion(value)])
        }
    }

    func testHostileControlAndOversizedProfileVersionsRejectWholeEvent() {
        for version in [
            "1; private=text", "1\n2", "1\u{0000}2", "1\u{202E}2", "１.0",
            ".1", "1.", "1..2", "1.2.3.4", "1234567890", String(repeating: "1", count: 1_024),
        ] {
            let candidate = DiagnosticEventCandidate(
                correlationID: CorrelationID(),
                layer: .profile,
                code: .profileRecognized,
                attributes: [.count(1), .profileVersion(ProfileVersion(version))]
            )
            XCTAssertThrowsError(try DiagnosticPrivacyFilter.review(candidate)) { error in
                XCTAssertEqual(error as? DiagnosticPrivacyRejection, .invalidProfileVersion)
            }
        }
    }

    func testForbiddenValuePrecedesInvalidProfileVersionAndLayer() {
        let candidate = DiagnosticEventCandidate(
            correlationID: CorrelationID(),
            layer: .transport,
            code: .profileRecognized,
            attributes: [
                .profileVersion(ProfileVersion("1\nprivate")),
                .forbidden(.pin),
            ]
        )
        XCTAssertThrowsError(try DiagnosticPrivacyFilter.review(candidate)) { error in
            XCTAssertEqual(error as? DiagnosticPrivacyRejection, .forbidden(.pin))
        }
    }
}
