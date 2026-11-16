import Foundation

public struct OperationLease: Hashable, Sendable {
    public let id: UUID
    public let generation: ConnectionGeneration
    public let metadata: CardOperationMetadata

    public init(
        id: UUID = UUID(),
        generation: ConnectionGeneration,
        metadata: CardOperationMetadata
    ) {
        self.id = id
        self.generation = generation
        self.metadata = metadata
    }
}

public struct AuthorizationLease: Hashable, Sendable {
    public let id: UUID
    public let generation: ConnectionGeneration

    public init(
        id: UUID = UUID(),
        generation: ConnectionGeneration
    ) {
        self.id = id
        self.generation = generation
    }
}

public enum TokenCoordinatorError: Error, Sendable, Equatable {
    case noConnection
    case staleGeneration
    case invalidConnection
    case operationInFlight
    case staleCompletion
    case invalidTransition
    case authorizationInFlight
    case staleAuthorization
}

public actor TokenCoordinator {
    private var generation: ConnectionGeneration?
    private var state: CardConnectionState = .absent
    private var publicationState: PublicationState = .unpublished
    private var lifecycleState: TokenLifecycleState = .absent
    private var activeOperation: OperationLease?
    private var activeAuthorization: AuthorizationLease?

    public init() {}

    @discardableResult
    public func beginConnection() -> ConnectionGeneration {
        let next = ConnectionGeneration()
        generation = next
        state = .candidate
        publicationState = .unpublished
        lifecycleState = .candidate
        activeOperation = nil
        activeAuthorization = nil
        return next
    }

    public func markRecognized(
        generation expected: ConnectionGeneration,
        profileVersion: ProfileVersion
    ) throws {
        try requireCurrent(expected)
        state = .recognized(profileVersion: profileVersion)
    }

    public func markPublished(generation expected: ConnectionGeneration) throws {
        try requireCurrent(expected)
        guard case .recognized = state else {
            throw TokenCoordinatorError.invalidConnection
        }
        publicationState = .published
        lifecycleState = .publicReady
    }

    public func invalidate(generation expected: ConnectionGeneration) {
        guard generation == expected else { return }
        state = .invalid
        publicationState = .invalid
        lifecycleState = .invalid
        activeOperation = nil
        activeAuthorization = nil
        generation = nil
    }

    public func snapshot() -> CardConnectionSnapshot {
        CardConnectionSnapshot(
            generation: generation,
            state: state,
            publicationState: publicationState
        )
    }

    public func lifecycleSnapshot() -> TokenLifecycleState {
        lifecycleState
    }

    public func beginAuthorization(
        generation expected: ConnectionGeneration
    ) throws -> AuthorizationLease {
        try requireCurrent(expected)
        guard lifecycleState == .publicReady else {
            throw TokenCoordinatorError.invalidTransition
        }
        guard activeAuthorization == nil else {
            throw TokenCoordinatorError.authorizationInFlight
        }
        let lease = AuthorizationLease(generation: expected)
        activeAuthorization = lease
        lifecycleState = .authPending
        return lease
    }

    public func completeAuthorization(_ lease: AuthorizationLease) throws {
        guard activeAuthorization == lease else {
            throw TokenCoordinatorError.staleAuthorization
        }
        try requireCurrent(lease.generation)
        guard lifecycleState == .authPending else {
            throw TokenCoordinatorError.invalidTransition
        }
        activeAuthorization = nil
        lifecycleState = .authorized
    }

    public func cancelAuthorization(_ lease: AuthorizationLease) throws {
        guard activeAuthorization == lease else {
            throw TokenCoordinatorError.staleAuthorization
        }
        try requireCurrent(lease.generation)
        guard lifecycleState == .authPending else {
            throw TokenCoordinatorError.invalidTransition
        }
        activeAuthorization = nil
        lifecycleState = .publicReady
    }

    public func perform<Result: Sendable>(
        generation expected: ConnectionGeneration,
        metadata: CardOperationMetadata,
        operation: @Sendable () async throws -> Result
    ) async throws -> Result {
        let lease = try beginOperation(generation: expected, metadata: metadata)
        do {
            let result = try await operation()
            guard activeOperation == lease, generation == expected else {
                throw TokenCoordinatorError.staleCompletion
            }
            activeOperation = nil
            completeLifecycleOperation(metadata, succeeded: true)
            return result
        } catch {
            if activeOperation == lease {
                activeOperation = nil
                completeLifecycleOperation(metadata, succeeded: false)
            }
            throw error
        }
    }

    private func beginOperation(
        generation expected: ConnectionGeneration,
        metadata: CardOperationMetadata
    ) throws -> OperationLease {
        try requireCurrent(expected)
        switch metadata.kind {
        case .discover:
            guard lifecycleState == .candidate else {
                throw TokenCoordinatorError.invalidTransition
            }
        case .authenticate:
            guard lifecycleState == .authPending else {
                throw TokenCoordinatorError.invalidTransition
            }
        case .sign:
            guard lifecycleState == .authorized else {
                throw TokenCoordinatorError.invalidTransition
            }
        }
        guard activeOperation == nil else {
            throw TokenCoordinatorError.operationInFlight
        }
        let lease = OperationLease(generation: expected, metadata: metadata)
        activeOperation = lease
        return lease
    }

    private func completeLifecycleOperation(
        _ metadata: CardOperationMetadata,
        succeeded: Bool
    ) {
        if metadata.kind == .sign,
           lifecycleState == .authorized,
           !succeeded {
            lifecycleState = .publicReady
        }
    }

    private func requireCurrent(_ expected: ConnectionGeneration) throws {
        guard let generation else {
            throw TokenCoordinatorError.noConnection
        }
        guard generation == expected else {
            throw TokenCoordinatorError.staleGeneration
        }
        guard state != .invalid else {
            throw TokenCoordinatorError.invalidConnection
        }
    }
}
