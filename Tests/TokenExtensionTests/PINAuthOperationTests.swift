import CryptoTokenKit
import DNIeCore
import Foundation
import XCTest

final class PINAuthOperationTests: XCTestCase {
    func testPasswordIsClearedBeforeOneSynchronousConsumption() throws {
        var received: Data?
        weak var observedOperation: DNIePINAuthOperation?
        let operation = DNIePINAuthOperation { bytes in
            XCTAssertNil(observedOperation?.password)
            received = bytes
        }
        observedOperation = operation
        operation.password = "Public7!"

        try operation.finish()

        XCTAssertEqual(received, Data("Public7!".utf8))
        XCTAssertNil(operation.password)
        XCTAssertThrowsError(try operation.finish()) { error in
            XCTAssertEqual((error as NSError).domain, TKErrorDomain)
            XCTAssertEqual((error as NSError).code, TKError.Code.corruptedData.rawValue)
        }
    }

    func testCancellationNeverInvokesHandler() {
        var invoked = false
        var cancellations = 0
        let operation = DNIePINAuthOperation(
            onCancel: { cancellations += 1 },
            handler: { _ in invoked = true }
        )

        XCTAssertThrowsError(try operation.finish()) { error in
            XCTAssertEqual((error as NSError).domain, TKErrorDomain)
            XCTAssertEqual((error as NSError).code, TKError.Code.canceledByUser.rawValue)
        }
        XCTAssertFalse(invoked)
        XCTAssertEqual(cancellations, 1)
        XCTAssertNil(operation.password)
        XCTAssertThrowsError(try operation.finish())
        XCTAssertEqual(cancellations, 1)
    }

    func testDocumentedPINFailuresMapWithoutAutomaticSecondConsumption() {
        for failure in [PINAuthOperationFailure.incorrect, .blocked] {
            var calls = 0
            let operation = DNIePINAuthOperation { _ in
                calls += 1
                throw failure
            }
            operation.password = "Public7!"

            XCTAssertThrowsError(try operation.finish()) { error in
                XCTAssertEqual((error as NSError).domain, TKErrorDomain)
                XCTAssertEqual((error as NSError).code, TKError.Code.authenticationFailed.rawValue)
            }
            XCTAssertEqual(calls, 1)
            XCTAssertNil(operation.password)
        }
    }

    func testTransportAndUnknownFailuresMapConservatively() {
        for (failure, expectedCode) in [
            (AnyError(CardTransportError.removed), TKError.Code.communicationError),
            (AnyError(TestFailure()), TKError.Code.corruptedData),
        ] {
            let operation = DNIePINAuthOperation { _ in throw failure.error }
            operation.password = "Public7!"

            XCTAssertThrowsError(try operation.finish()) { error in
                XCTAssertEqual((error as NSError).domain, TKErrorDomain)
                XCTAssertEqual((error as NSError).code, expectedCode.rawValue)
            }
            XCTAssertNil(operation.password)
        }
    }

    func testVolatileLeaseRequiresExactSessionGenerationAndConstraint() async throws {
        let sessionID = UUID()
        let generation = ConnectionGeneration()
        let binding = VolatilePINLeaseBinding(
            sessionID: sessionID,
            generation: generation,
            constraint: Data([0xA1])
        )
        let store = VolatilePINLeaseStore()
        store.install(credential: Data([0x31, 0x32, 0x33]), binding: binding)

        let matched = try await store.withCredential(binding: binding) {
            $0 == Data([0x31, 0x32, 0x33])
        }
        XCTAssertTrue(matched)
        XCTAssertEqual(store.snapshot(), .available)

        let foreignBinding = VolatilePINLeaseBinding(
            sessionID: UUID(),
            generation: generation,
            constraint: Data([0xA1])
        )
        await XCTAssertThrowsErrorAsync(
            try await store.withCredential(binding: foreignBinding) { _ in true }
        ) { error in
            XCTAssertEqual(error as? VolatilePINLeaseError, .unavailable)
        }
        XCTAssertEqual(store.snapshot(), .empty)
        await XCTAssertThrowsErrorAsync(
            try await store.withCredential(binding: binding) { _ in true }
        )
    }

    func testVolatileLeaseExpiresAndInvalidatesWithoutExposingCredential() async throws {
        let clock = ContinuousClock()
        let start = clock.now
        let binding = VolatilePINLeaseBinding(
            sessionID: UUID(),
            generation: ConnectionGeneration(),
            constraint: Data([0xB1])
        )
        let store = VolatilePINLeaseStore(lifetime: .seconds(60))
        store.install(
            credential: Data([0x34, 0x35, 0x36]),
            binding: binding,
            now: start
        )

        XCTAssertEqual(
            store.snapshot(now: start.advanced(by: .seconds(59))),
            .available
        )
        XCTAssertEqual(
            store.snapshot(now: start.advanced(by: .seconds(60))),
            .empty
        )
        await XCTAssertThrowsErrorAsync(
            try await store.withCredential(binding: binding) { _ in true }
        )

        store.install(credential: Data([0x37]), binding: binding)
        store.invalidate()
        XCTAssertEqual(store.snapshot(), .empty)
    }

    func testVolatileLeaseHasActiveTimeoutCleanup() async throws {
        let binding = VolatilePINLeaseBinding(
            sessionID: UUID(),
            generation: ConnectionGeneration(),
            constraint: Data([0xC1])
        )
        let store = VolatilePINLeaseStore(lifetime: .milliseconds(20))
        store.install(credential: Data([0x38]), binding: binding)

        try await Task<Never, Never>.sleep(for: .milliseconds(50))

        XCTAssertEqual(store.snapshot(), .empty)
    }

    func testSourceContainsOnlyBoundedMemoryCredentialRetention() throws {
        let source = try String(
            contentsOf: repositoryRoot().appendingPathComponent("TokenExtension/PINAuthOperation.swift"),
            encoding: .utf8
        )
        for forbidden in ["Logger", "os_log", "print(", "passwordBytes = Data()"] {
            XCTAssertFalse(source.contains(forbidden))
        }
        for forbidden in ["UserDefaults", "Keychain", "SecItem", "write(to:", "String(data:"] {
            XCTAssertFalse(source.contains(forbidden))
        }
        XCTAssertTrue(source.contains("password = nil"))
        XCTAssertTrue(source.contains("CryptoPrimitives.secureZero(&passwordBytes)"))
        XCTAssertTrue(source.contains("productionLifetime: Duration = .seconds(60)"))
        XCTAssertTrue(source.contains("CryptoPrimitives.secureZero(&credential)"))
        XCTAssertTrue(source.contains("CryptoPrimitives.secureZero(&workingCredential)"))
    }

    private func repositoryRoot() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }
}

private func XCTAssertThrowsErrorAsync<T>(
    _ expression: @autoclosure () async throws -> T,
    _ errorHandler: (Error) -> Void = { _ in },
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("Expected expression to throw", file: file, line: line)
    } catch {
        errorHandler(error)
    }
}

private struct TestFailure: Error {}

private struct AnyError {
    let error: any Error
    init(_ error: any Error) { self.error = error }
}
