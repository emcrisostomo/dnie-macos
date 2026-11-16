import DNIeCore
import XCTest

final class DiagnosticsTests: XCTestCase {
    func testEveryForbiddenValueClassIsRejected() {
        for valueClass in ForbiddenDiagnosticValueClass.allCases {
            let candidate = DiagnosticEventCandidate(
                correlationID: CorrelationID(),
                layer: .lifecycle,
                code: .operationRejected,
                attributes: [.forbidden(valueClass)]
            )

            XCTAssertThrowsError(try DiagnosticPrivacyFilter.review(candidate)) { error in
                XCTAssertEqual(
                    error as? DiagnosticPrivacyRejection,
                    .forbidden(valueClass)
                )
            }
        }
    }

    func testClosedSafeAttributesSurviveReview() throws {
        let candidate = DiagnosticEventCandidate(
            correlationID: CorrelationID(),
            layer: .transport,
            code: .operationCompleted,
            attributes: [
                .profileVersion(ProfileVersion("1.0.0")),
                .durationMilliseconds(12),
                .count(1),
                .errorCategory(.communication),
            ]
        )

        let event = try DiagnosticPrivacyFilter.review(candidate)
        XCTAssertEqual(event.attributes.count, 4)
    }

    func testProcessCardAuthorizationAndRecoveryCodesAreClosedAndDurationSafe() throws {
        let lifecycleCodes: [DiagnosticEventCode] = [
            .processStarted,
            .processStopped,
            .cardInserted,
            .cardRemoved,
            .authorizationStarted,
            .authorizationCompleted,
            .recoveryStarted,
            .recoveryCompleted,
        ]
        let timer = MonotonicDiagnosticTimer(
            startedAtUptimeNanoseconds: 1_000_000
        )

        for code in lifecycleCodes {
            let event = try DiagnosticPrivacyFilter.review(
                DiagnosticEventCandidate(
                    correlationID: CorrelationID(),
                    layer: .lifecycle,
                    code: code,
                    attributes: [timer.durationAttribute(
                        endingAtUptimeNanoseconds: 13_000_000
                    )]
                )
            )
            XCTAssertEqual(event.code, code)
            XCTAssertEqual(event.attributes, [.durationMilliseconds(12)])
        }
    }
}
