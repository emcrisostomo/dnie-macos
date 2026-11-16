import Foundation

public struct PINAuthorizationLease: Hashable, Sendable {
    public let id: UUID
    public let generation: ConnectionGeneration
    public let constraint: Data

    public init(
        id: UUID = UUID(),
        generation: ConnectionGeneration,
        constraint: Data
    ) {
        self.id = id
        self.generation = generation
        self.constraint = constraint
    }
}

public enum PINAuthorizationState: Sendable, Equatable {
    case idle
    case pending
    case authorized
    case failed(PINVerificationResult)
    case invalid
}

public enum PINAuthorizationError: Error, Sendable, Equatable {
    case operationInFlight
    case staleOperation
}

public actor PINAuthorizationController {
    private var state: PINAuthorizationState = .idle
    private var activeLease: PINAuthorizationLease?
    private var authorizedContext: (generation: ConnectionGeneration, constraint: Data)?
    private var stateGeneration: ConnectionGeneration?
    private var submissions = 0

    public init() {}

    public func begin(
        generation: ConnectionGeneration,
        constraint: Data
    ) throws -> PINAuthorizationLease {
        guard activeLease == nil else {
            throw PINAuthorizationError.operationInFlight
        }
        let lease = PINAuthorizationLease(
            generation: generation,
            constraint: constraint
        )
        activeLease = lease
        authorizedContext = nil
        stateGeneration = generation
        state = .pending
        return lease
    }

    public func cancel(_ lease: PINAuthorizationLease) throws {
        try requireActive(lease)
        activeLease = nil
        authorizedContext = nil
        stateGeneration = nil
        state = .idle
    }

    public func complete(
        _ lease: PINAuthorizationLease,
        result: PINVerificationResult
    ) throws {
        try requireActive(lease)
        submissions += 1
        activeLease = nil

        switch result {
        case .accepted:
            authorizedContext = (lease.generation, lease.constraint)
            state = .authorized
        case .incorrect, .blocked:
            authorizedContext = nil
            state = .failed(result)
        case .unknown:
            authorizedContext = nil
            state = .invalid
        }
    }

    public func invalidate(generation: ConnectionGeneration) {
        guard stateGeneration == generation else { return }
        activeLease = nil
        authorizedContext = nil
        stateGeneration = nil
        state = .invalid
    }

    public func snapshot() -> PINAuthorizationState {
        state
    }

    public func submissionCount() -> Int {
        submissions
    }

    public func shouldRetryAutomatically() -> Bool {
        false
    }

    public func isAuthorized(
        generation: ConnectionGeneration,
        constraint: Data
    ) -> Bool {
        authorizedContext?.generation == generation
            && authorizedContext?.constraint == constraint
    }

    private func requireActive(_ lease: PINAuthorizationLease) throws {
        guard activeLease == lease else {
            throw PINAuthorizationError.staleOperation
        }
    }
}
