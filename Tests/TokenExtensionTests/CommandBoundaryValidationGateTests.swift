import CryptoTokenKit
import Darwin
import DNIeCore
import Foundation
import XCTest

final class CommandBoundaryValidationGateTests: XCTestCase {
    func testClosedGateIsUnavailableAndCannotDelayOrdinaryPath() {
        let gate = ClosedCommandBoundaryValidationGate()

        XCTAssertEqual(gate.wait(phase: .discovery, cardIsValid: { true }, cancellationRequested: { false }), .unavailable)
        XCTAssertEqual(gate.wait(phase: .pinVerification, cardIsValid: { false }, cancellationRequested: { true }), .unavailable)
        XCTAssertEqual(gate.wait(phase: .signing, cardIsValid: { true }, cancellationRequested: { false }), .unavailable)
    }

    func testStateClassifiesPresentRemovalTimeoutAndCancellation() {
        let state = CommandBoundaryGateState()

        XCTAssertTrue(state.begin())
        XCTAssertEqual(
            state.complete(released: true, cancelled: false, cardIsValid: true),
            .present
        )
        XCTAssertTrue(state.begin())
        XCTAssertEqual(
            state.complete(released: true, cancelled: false, cardIsValid: false),
            .removed
        )
        XCTAssertTrue(state.begin())
        XCTAssertEqual(
            state.complete(released: false, cancelled: false, cardIsValid: true),
            .timeout
        )
        XCTAssertTrue(state.begin())
        XCTAssertEqual(
            state.complete(released: true, cancelled: true, cardIsValid: true),
            .cancelled
        )
    }

    func testConcurrentAndLateCompletionAreMalformed() {
        let state = CommandBoundaryGateState()

        XCTAssertTrue(state.begin())
        XCTAssertFalse(state.begin())
        XCTAssertEqual(
            state.complete(released: true, cancelled: false, cardIsValid: true),
            .present
        )
        XCTAssertEqual(
            state.complete(released: true, cancelled: false, cardIsValid: true),
            .malformed
        )
    }

    func testGateSourcesPlaceAllThreeBoundariesBeforeCardWork() throws {
        let root = repositoryRoot()
        let token = try String(
            contentsOf: root.appendingPathComponent("TokenExtension/Token.swift"),
            encoding: .utf8
        )
        let pin = try String(
            contentsOf: root.appendingPathComponent("TokenExtension/TokenSession.swift"),
            encoding: .utf8
        )
        let gate = try String(
            contentsOf: root.appendingPathComponent(
                "TokenExtension/CommandBoundaryValidationGate.swift"
            ),
            encoding: .utf8
        )

        XCTAssertLessThan(
            try XCTUnwrap(token.range(of: ".discovery")).lowerBound,
            try XCTUnwrap(token.range(of: "Self.waitForDiscovery(")).lowerBound
        )
        XCTAssertLessThan(
            try XCTUnwrap(pin.range(of: ".pinVerification")).lowerBound,
            try XCTUnwrap(pin.range(of: "establisher.establishPINChannel()")).lowerBound
        )
        let firstSign = try XCTUnwrap(pin.range(of: "operation.sign.channel_preparation=established_user_channel"))
        let signingGate = try XCTUnwrap(pin.range(of: ".signing", range: firstSign.upperBound..<pin.endIndex))
        let signingCommand = try XCTUnwrap(pin.range(of: "DNIeSigning.signSHA256Digest(", range: signingGate.upperBound..<pin.endIndex))
        XCTAssertLessThan(signingGate.lowerBound, signingCommand.lowerBound)
        let refresh = try XCTUnwrap(pin.range(of: "if signLease.preparation == .refreshUserChannel"))
        let established = try XCTUnwrap(pin.range(of: "} else {", range: refresh.upperBound..<pin.endIndex))
        XCTAssertFalse(pin[refresh.lowerBound..<established.lowerBound].contains(".signing"))
        XCTAssertFalse(gate.contains("card.transmit("))
        XCTAssertTrue(gate.contains("#if T075_COMMAND_BOUNDARY_VALIDATION"))
        XCTAssertTrue(gate.contains("ClosedCommandBoundaryValidationGate"))
        XCTAssertTrue(gate.contains("cancellationRequested"))
        XCTAssertTrue(gate.contains("CommandBoundarySignalSafety.installIgnoreDisposition()"))
        XCTAssertFalse(token.contains("Task.isCancelled"))
        XCTAssertFalse(pin.contains("Task.isCancelled"))
        XCTAssertTrue(pin.contains("lifecycle.isAuthorizationAwaitingInput(lifecycleClaim)"))
        XCTAssertTrue(pin.contains("lifecycle.isSignActive(signLease)"))
    }

    #if T075_COMMAND_BOUNDARY_VALIDATION
    func testActualSignalGateStopsImmediatelyWhenCancellationIsAlreadyRequested() {
        let gate = SignalCommandBoundaryValidationGate()

        XCTAssertEqual(
            gate.wait(
                phase: .pinVerification,
                cardIsValid: { true },
                cancellationRequested: { true }
            ),
            .cancelled
        )
    }

    func testLifecycleInvalidationDuringActualGateIsTerminalAndLateSignalCannotReleaseWork() throws {
        let generation = ConnectionGeneration()
        let lifecycle = TokenSessionLifecycleCoordinator(generation: generation)
        let claim = try lifecycle.claimAuthorization(
            sessionID: UUID(),
            generation: generation
        )
        try lifecycle.markAuthorizationAwaitingInput(claim)
        let gate = SignalCommandBoundaryValidationGate()

        DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(20)) {
            lifecycle.invalidate(generation: generation)
        }
        let outcome = gate.wait(
            phase: .pinVerification,
            cardIsValid: { true },
            cancellationRequested: {
                !lifecycle.isAuthorizationAwaitingInput(claim)
            }
        )

        XCTAssertEqual(outcome, .cancelled)
        XCTAssertEqual(lifecycle.snapshot(), .invalid)
        var cardCommands = 0
        if outcome == .present {
            cardCommands += 1
        }
        XCTAssertEqual(cardCommands, 0)

        XCTAssertEqual(kill(getpid(), SIGUSR1), 0)
        let laterSource = expectation(description: "late release after cancellation is ignored")
        laterSource.isInverted = true
        let source = DispatchSource.makeSignalSource(signal: SIGUSR1, queue: .global())
        source.setEventHandler { laterSource.fulfill() }
        source.resume()
        wait(for: [laterSource], timeout: 0.1)
        source.cancel()
    }

    func testLateSIGUSR1IsIgnoredAfterRealSourceCleanupAndCannotReleaseNextSource() {
        CommandBoundarySignalSafety.installIgnoreDisposition()
        let completed = expectation(description: "first source is cleaned")
        let first = DispatchSource.makeSignalSource(signal: SIGUSR1, queue: .global())
        first.setEventHandler { }
        first.resume()
        first.cancel()
        completed.fulfill()
        wait(for: [completed], timeout: 1)

        XCTAssertEqual(kill(getpid(), SIGUSR1), 0)
        let nextRelease = expectation(description: "late signal must not release next source")
        nextRelease.isInverted = true
        let next = DispatchSource.makeSignalSource(signal: SIGUSR1, queue: .global())
        next.setEventHandler { nextRelease.fulfill() }
        next.resume()
        wait(for: [nextRelease], timeout: 0.1)
        next.cancel()
    }
    #endif

    func testStoppedPINAndSigningPathsInvalidateBeforeReturning() throws {
        let source = try String(
            contentsOf: repositoryRoot().appendingPathComponent(
                "TokenExtension/TokenSession.swift"
            ),
            encoding: .utf8
        )
        let pinGate = try XCTUnwrap(source.range(of: ".pinVerification"))
        let pinFailure = try XCTUnwrap(source.range(
            of: "pinLease.invalidate()",
            range: pinGate.upperBound..<source.endIndex
        ))
        XCTAssertLessThan(pinGate.lowerBound, pinFailure.lowerBound)

        let signingGate = try XCTUnwrap(source.range(of: ".signing"))
        let signingFailure = try XCTUnwrap(source.range(
            of: "invalidate(\n                generation: generation,\n                cardHandle: cardHandle,",
            range: signingGate.upperBound..<source.endIndex
        ))
        XCTAssertLessThan(signingGate.lowerBound, signingFailure.lowerBound)
    }

    func testPINOperationMapsStoppedGateWithoutSecondConsumption() {
        var calls = 0
        let operation = DNIePINAuthOperation { _ in
            calls += 1
            throw CommandBoundaryGateError.stopped(.removed)
        }
        operation.password = "Public7!"

        XCTAssertThrowsError(try operation.finish()) { error in
            XCTAssertEqual((error as NSError).code, TKError.Code.communicationError.rawValue)
        }
        XCTAssertEqual(calls, 1)
        XCTAssertNil(operation.password)
    }

    private func repositoryRoot() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }
}
