import Darwin
import Foundation
import OSLog

/// A validation-only pause placed immediately before a card-command boundary.
///
/// Normal builds compile this type too, but select the unavailable gate and therefore cannot
/// wait for a signal or alter the ordinary provider path. The explicit validation compilation
/// condition is the only route that enables a finite signal-backed gate.
enum CommandBoundaryPhase: String, CaseIterable, Sendable {
    case discovery
    case pinVerification = "pin_verification"
    case signing
}

enum CommandBoundaryGateOutcome: String, Sendable, Equatable {
    case unavailable
    case present
    case removed
    case timeout
    case cancelled
    case malformed
}

enum CommandBoundaryGateError: Error, Sendable, Equatable {
    case stopped(CommandBoundaryGateOutcome)
}

protocol CommandBoundaryValidationGating: Sendable {
    func wait(
        phase: CommandBoundaryPhase,
        cardIsValid: @escaping () -> Bool,
        cancellationRequested: @escaping () -> Bool
    ) -> CommandBoundaryGateOutcome
}

struct ClosedCommandBoundaryValidationGate: CommandBoundaryValidationGating {
    func wait(
        phase _: CommandBoundaryPhase,
        cardIsValid _: @escaping () -> Bool,
        cancellationRequested _: @escaping () -> Bool
    ) -> CommandBoundaryGateOutcome {
        .unavailable
    }
}

/// Serializes and classifies the finite validation wait independently of card APIs. Keeping this
/// logic data-only gives the offline tests an exact no-command oracle.
final class CommandBoundaryGateState: @unchecked Sendable {
    private let lock = NSLock()
    private var active = false

    func begin() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !active else { return false }
        active = true
        return true
    }

    func complete(
        released: Bool,
        cancelled: Bool,
        cardIsValid: Bool
    ) -> CommandBoundaryGateOutcome {
        lock.lock()
        defer { lock.unlock() }
        guard active else { return .malformed }
        defer { active = false }
        guard !cancelled else { return .cancelled }
        guard released else { return .timeout }
        return cardIsValid ? .present : .removed
    }
}

enum CommandBoundaryValidationGate {
    private static let logger = Logger(
        subsystem: "org.dniemacos.dnietoken",
        category: "command-boundary-validation"
    )

    #if T075_COMMAND_BOUNDARY_VALIDATION
    private static let implementation: any CommandBoundaryValidationGating =
        SignalCommandBoundaryValidationGate()
    #else
    private static let implementation: any CommandBoundaryValidationGating =
        ClosedCommandBoundaryValidationGate()
    #endif

    static func require(
        _ phase: CommandBoundaryPhase,
        cardIsValid: @escaping () -> Bool,
        cancellationRequested: @escaping () -> Bool = { Task.isCancelled }
    ) throws {
        let outcome = implementation.wait(
            phase: phase,
            cardIsValid: cardIsValid,
            cancellationRequested: cancellationRequested
        )
        switch outcome {
        case .unavailable, .present:
            return
        case .removed, .timeout, .cancelled, .malformed:
            logger.notice(
                "command_boundary.stop phase=\(phase.rawValue, privacy: .public) outcome=\(outcome.rawValue, privacy: .public) card_command_sent=false automatic_retry=false"
            )
            throw CommandBoundaryGateError.stopped(outcome)
        }
    }
}

#if T075_COMMAND_BOUNDARY_VALIDATION
final class SignalCommandBoundaryValidationGate: CommandBoundaryValidationGating, @unchecked Sendable {
    private static let timeoutSeconds = 120
    private let state = CommandBoundaryGateState()

    func wait(
        phase: CommandBoundaryPhase,
        cardIsValid: @escaping () -> Bool,
        cancellationRequested: @escaping () -> Bool
    ) -> CommandBoundaryGateOutcome {
        guard state.begin() else { return .malformed }
        CommandBoundarySignalSafety.installIgnoreDisposition()
        let semaphore = DispatchSemaphore(value: 0)
        let source = DispatchSource.makeSignalSource(
            signal: SIGUSR1,
            queue: DispatchQueue.global(qos: .userInitiated)
        )
        let releaseLock = NSLock()
        var released = false
        source.setEventHandler {
            releaseLock.lock()
            released = true
            releaseLock.unlock()
            semaphore.signal()
        }
        source.resume()
        defer { source.cancel() }

        CommandBoundaryValidationGateLogger.ready(
            phase: phase,
            timeoutSeconds: Self.timeoutSeconds,
            cardIsValid: cardIsValid()
        )
        let deadline = DispatchTime.now() + .seconds(Self.timeoutSeconds)
        var result: DispatchTimeoutResult = .timedOut
        var cancelled = cancellationRequested()
        while !cancelled, DispatchTime.now() < deadline {
            result = semaphore.wait(timeout: .now() + .milliseconds(100))
            if result == .success { break }
            cancelled = cancellationRequested()
        }
        releaseLock.lock()
        let didRelease = released
        releaseLock.unlock()
        let outcome = state.complete(
            released: didRelease && result == .success,
            cancelled: cancelled,
            cardIsValid: cardIsValid()
        )
        CommandBoundaryValidationGateLogger.completed(phase: phase, outcome: outcome)
        return outcome
    }
}

/// SIGUSR1 is a validation-only release signal. Keeping it ignored between finite Dispatch
/// sources prevents a helper that arrives after cleanup from terminating the extension or waking
/// a later boundary. The source itself is the only consumer while a gate is active.
enum CommandBoundarySignalSafety {
    private static let lock = NSLock()

    static func installIgnoreDisposition() {
        lock.lock()
        Darwin.signal(SIGUSR1, SIG_IGN)
        lock.unlock()
    }
}

private enum CommandBoundaryValidationGateLogger {
    private static let logger = Logger(
        subsystem: "org.dniemacos.dnietoken",
        category: "command-boundary-validation"
    )

    static func ready(
        phase: CommandBoundaryPhase,
        timeoutSeconds: Int,
        cardIsValid: Bool
    ) {
        logger.notice(
            "command_boundary.ready phase=\(phase.rawValue, privacy: .public) pid=\(ProcessInfo.processInfo.processIdentifier, privacy: .public) release_signal=SIGUSR1 timeout_seconds=\(timeoutSeconds, privacy: .public) card_valid=\(cardIsValid, privacy: .public) card_command_sent=false automatic_retry=false payload_logged=false"
        )
    }

    static func completed(phase: CommandBoundaryPhase, outcome: CommandBoundaryGateOutcome) {
        logger.notice(
            "command_boundary.complete phase=\(phase.rawValue, privacy: .public) outcome=\(outcome.rawValue, privacy: .public) card_command_sent=false automatic_retry=false payload_logged=false"
        )
    }
}
#endif
