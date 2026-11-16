import Foundation

public struct PKCS15DirectoryLimits: Sendable, Equatable {
    public let maximumEncodedLength: Int
    public let maximumRecords: Int
    public let maximumIdentifierLength: Int
    public let maximumLabelLength: Int
    public let maximumPathComponents: Int

    public init(
        maximumEncodedLength: Int = 16 * 1_024,
        maximumRecords: Int = 64,
        maximumIdentifierLength: Int = 64,
        maximumLabelLength: Int = 128,
        maximumPathComponents: Int = 8
    ) {
        precondition(maximumEncodedLength > 0)
        precondition(maximumRecords > 0)
        precondition(maximumIdentifierLength > 0)
        precondition(maximumLabelLength > 0)
        precondition(maximumPathComponents > 0)
        self.maximumEncodedLength = maximumEncodedLength
        self.maximumRecords = maximumRecords
        self.maximumIdentifierLength = maximumIdentifierLength
        self.maximumLabelLength = maximumLabelLength
        self.maximumPathComponents = maximumPathComponents
    }
}

public struct PKCS15DirectoryParseResult: Sendable, Equatable {
    public let objects: [PKCS15ObjectReference]
    public let zeroFillByteCount: Int
    public let ffFillByteCount: Int

    public init(
        objects: [PKCS15ObjectReference],
        zeroFillByteCount: Int,
        ffFillByteCount: Int
    ) {
        self.objects = objects
        self.zeroFillByteCount = zeroFillByteCount
        self.ffFillByteCount = ffFillByteCount
    }
}

public struct PKCS15DirectoryReader: Sendable {
    private let limits: PKCS15DirectoryLimits

    public init(limits: PKCS15DirectoryLimits = PKCS15DirectoryLimits()) {
        self.limits = limits
    }

    public func certificateObjects(from data: Data) throws -> PKCS15DirectoryParseResult {
        try objects(from: data, type: .certificate)
    }

    public func privateKeyObjects(from data: Data) throws -> PKCS15DirectoryParseResult {
        try objects(from: data, type: .privateKey)
    }

    private func objects(
        from data: Data,
        type: PKCS15ObjectType
    ) throws -> PKCS15DirectoryParseResult {
        let directory = try BoundedDERReader.parseDirectory(
            data,
            maximumEncodedLength: limits.maximumEncodedLength,
            maximumRecords: limits.maximumRecords
        )
        guard !directory.records.isEmpty else {
            throw PKCS15ParsingError.invalidDirectory
        }

        let objects = try directory.records.map { record in
            guard record.tag == 0x30 else {
                throw PKCS15ParsingError.invalidRecord
            }
            let fields = try BoundedDERReader.parseAll(record.value, maximumElements: 12)
            guard fields.count == 3,
                  fields[0].tag == 0x30,
                  fields[1].tag == 0x30,
                  fields[2].tag == 0xA1 else {
                throw PKCS15ParsingError.invalidRecord
            }

            switch type {
            case .certificate:
                return PKCS15ObjectReference(
                    objectType: type,
                    ckaID: try identifier(from: fields[1]),
                    label: try label(from: fields[0]),
                    path: try path(from: fields[2]),
                    usage: [],
                    keyReference: nil,
                    authenticationReference: nil
                )
            case .privateKey:
                return try privateKeyReference(fields: fields)
            case .authenticationReference:
                throw PKCS15ParsingError.invalidRecord
            }
        }
        return PKCS15DirectoryParseResult(
            objects: objects,
            zeroFillByteCount: directory.zeroFillByteCount,
            ffFillByteCount: directory.ffFillByteCount
        )
    }

    private func privateKeyReference(
        fields: [BoundedDERTLV]
    ) throws -> PKCS15ObjectReference {
        let commonObject = try commonObjectMetadata(from: fields[0])
        let commonKey = try commonKeyMetadata(from: fields[1])
        let rsa = try rsaPrivateKeyMetadata(from: fields[2])
        guard commonKey.keyReference == UInt8(rsa.path.components.last! & 0x00FF) else {
            throw PKCS15ParsingError.invalidRecord
        }
        return PKCS15ObjectReference(
            objectType: .privateKey,
            ckaID: commonKey.identifier,
            label: commonObject.label,
            path: rsa.path,
            usage: commonKey.usage,
            keyReference: commonKey.keyReference,
            authenticationReference: commonObject.authenticationReference
        )
    }

    private func commonObjectMetadata(
        from attributes: BoundedDERTLV
    ) throws -> (label: String?, authenticationReference: Data?) {
        let fields = try BoundedDERReader.parseAll(attributes.value, maximumElements: 8)
        var index = 0
        var decodedLabel: String?
        if index < fields.count, fields[index].tag == 0x0C {
            guard fields[index].value.count <= limits.maximumLabelLength,
                  let label = String(data: fields[index].value, encoding: .utf8) else {
                throw PKCS15ParsingError.invalidLabel
            }
            decodedLabel = label
            index += 1
        }
        if index < fields.count, fields[index].tag == 0x03 {
            _ = try bitPositions(from: fields[index])
            index += 1
        }
        var authenticationReference: Data?
        if index < fields.count, fields[index].tag == 0x04 {
            authenticationReference = try boundedIdentifier(fields[index].value)
            index += 1
        }
        if index < fields.count, fields[index].tag == 0x02 {
            _ = try positiveInteger(fields[index])
            index += 1
        }
        // Target PASS evidence has no access-control-rule sequence. Do not silently
        // accept or reinterpret one until its semantics have a fixture and policy.
        guard index == fields.count else {
            throw PKCS15ParsingError.invalidRecord
        }
        return (decodedLabel, authenticationReference)
    }

    private func commonKeyMetadata(
        from attributes: BoundedDERTLV
    ) throws -> (identifier: Data, usage: KeyUsage, keyReference: UInt8) {
        let fields = try BoundedDERReader.parseAll(attributes.value, maximumElements: 8)
        guard fields.count >= 2,
              fields[0].tag == 0x04,
              fields[1].tag == 0x03 else {
            throw PKCS15ParsingError.invalidRecord
        }
        let identifier = try boundedIdentifier(fields[0].value)
        let usagePositions = try bitPositions(from: fields[1])
        let acceptedUsagePositions: Set<Int> = [2, 3, 9]
        guard usagePositions.isSubset(of: acceptedUsagePositions),
              !usagePositions.isDisjoint(with: Set([2, 3])) else {
            throw PKCS15ParsingError.invalidRecord
        }
        var index = 2
        if index < fields.count, fields[index].tag == 0x01 {
            guard fields[index].value.count == 1,
                  fields[index].value.first == 0xFF else {
                throw PKCS15ParsingError.invalidRecord
            }
            index += 1
        }
        if index < fields.count, fields[index].tag == 0x03 {
            let accessPositions = try bitPositions(from: fields[index])
            guard accessPositions.isSubset(of: Set([0, 2, 3, 4])) else {
                throw PKCS15ParsingError.invalidRecord
            }
            index += 1
        }
        guard index < fields.count, fields[index].tag == 0x02 else {
            throw PKCS15ParsingError.invalidRecord
        }
        let encodedReference = try positiveInteger(fields[index])
        guard (1...Int(UInt8.max)).contains(encodedReference) else {
            throw PKCS15ParsingError.invalidRecord
        }
        index += 1
        // Algorithm-reference forms were absent on the target and remain unsupported.
        guard index == fields.count else {
            throw PKCS15ParsingError.invalidRecord
        }
        return (identifier, [.sign], UInt8(encodedReference))
    }

    private func rsaPrivateKeyMetadata(
        from attributes: BoundedDERTLV
    ) throws -> (path: CardPath, modulusBits: Int) {
        let wrappers = try BoundedDERReader.parseAll(attributes.value, maximumElements: 2)
        guard wrappers.count == 1, wrappers[0].tag == 0x30 else {
            throw PKCS15ParsingError.invalidRecord
        }
        let fields = try BoundedDERReader.parseAll(wrappers[0].value, maximumElements: 3)
        guard (2...3).contains(fields.count),
              fields[0].tag == 0x30,
              fields[1].tag == 0x02 else {
            throw PKCS15ParsingError.invalidRecord
        }
        let parsedPath = try path(fromPathSequence: fields[0])
        let modulusBits = try positiveInteger(fields[1])
        guard modulusBits == 2_048 else {
            throw PKCS15ParsingError.invalidRecord
        }
        if fields.count == 3 {
            guard fields[2].tag == 0x02 else {
                throw PKCS15ParsingError.invalidRecord
            }
            _ = try positiveInteger(fields[2])
        }
        return (parsedPath, modulusBits)
    }

    private func identifier(from attributes: BoundedDERTLV) throws -> Data {
        let fields = try BoundedDERReader.parseAll(attributes.value, maximumElements: 4)
        guard let identifier = fields.first,
              identifier.tag == 0x04 else {
            throw PKCS15ParsingError.invalidIdentifier
        }
        return try boundedIdentifier(identifier.value)
    }

    private func boundedIdentifier(_ identifier: Data) throws -> Data {
        guard (1...limits.maximumIdentifierLength).contains(identifier.count) else {
            throw PKCS15ParsingError.invalidIdentifier
        }
        return identifier
    }

    private func label(from attributes: BoundedDERTLV) throws -> String? {
        let fields = try BoundedDERReader.parseAll(attributes.value, maximumElements: 8)
        guard let encoded = fields.first(where: { $0.tag == 0x0C }) else {
            return nil
        }
        guard encoded.value.count <= limits.maximumLabelLength,
              let label = String(data: encoded.value, encoding: .utf8) else {
            throw PKCS15ParsingError.invalidLabel
        }
        return label
    }

    private func path(from attributes: BoundedDERTLV) throws -> CardPath {
        let wrappers = try BoundedDERReader.parseAll(attributes.value, maximumElements: 4)
        guard let value = wrappers.first, value.tag == 0x30 else {
            throw PKCS15ParsingError.invalidPath
        }
        let fields = try BoundedDERReader.parseAll(value.value, maximumElements: 4)
        let octets: Data
        if let first = fields.first, first.tag == 0x04 {
            octets = first.value
        } else if let first = fields.first, first.tag == 0x30 {
            let pathFields = try BoundedDERReader.parseAll(first.value, maximumElements: 4)
            guard let path = pathFields.first,
                  path.tag == 0x04,
                  pathFields.dropFirst().allSatisfy({ $0.tag == 0x02 || $0.tag == 0x80 }) else {
                throw PKCS15ParsingError.invalidPath
            }
            octets = path.value
        } else {
            throw PKCS15ParsingError.invalidPath
        }

        return try cardPath(from: octets)
    }

    private func path(fromPathSequence sequence: BoundedDERTLV) throws -> CardPath {
        let fields = try BoundedDERReader.parseAll(sequence.value, maximumElements: 4)
        guard let octets = fields.first,
              octets.tag == 0x04,
              fields.dropFirst().allSatisfy({ $0.tag == 0x02 || $0.tag == 0x80 }) else {
            throw PKCS15ParsingError.invalidPath
        }
        return try cardPath(from: octets.value)
    }

    private func cardPath(from octets: Data) throws -> CardPath {
        let bytes = [UInt8](octets)
        guard bytes.count >= 2,
              bytes.count.isMultiple(of: 2),
              bytes.count / 2 <= limits.maximumPathComponents else {
            throw PKCS15ParsingError.invalidPath
        }
        let components = stride(from: 0, to: bytes.count, by: 2).map {
            UInt16(bytes[$0]) << 8 | UInt16(bytes[$0 + 1])
        }
        guard components.allSatisfy({ $0 != 0x0000 && $0 != 0xFFFF }) else {
            throw PKCS15ParsingError.invalidPath
        }
        return CardPath(components: components)
    }

    private func bitPositions(from field: BoundedDERTLV) throws -> Set<Int> {
        guard field.tag == 0x03, !field.value.isEmpty else {
            throw PKCS15ParsingError.invalidRecord
        }
        let bytes = [UInt8](field.value)
        let unusedBits = Int(bytes[0])
        guard (0...7).contains(unusedBits), bytes.count > 1 else {
            throw PKCS15ParsingError.invalidRecord
        }
        let payload = Array(bytes.dropFirst())
        if unusedBits > 0 {
            let unusedMask = UInt8((1 << unusedBits) - 1)
            guard payload.last! & unusedMask == 0 else {
                throw PKCS15ParsingError.invalidRecord
            }
        }
        let bitCount = payload.count * 8 - unusedBits
        return Set((0..<bitCount).filter { position in
            payload[position / 8] & (0x80 >> UInt8(position % 8)) != 0
        })
    }

    private func positiveInteger(_ field: BoundedDERTLV) throws -> Int {
        guard field.tag == 0x02,
              !field.value.isEmpty,
              field.value.count <= MemoryLayout<Int>.size,
              field.value.first! & 0x80 == 0 else {
            throw PKCS15ParsingError.invalidRecord
        }
        let bytes = [UInt8](field.value)
        guard bytes.count == 1 || bytes[0] != 0 || bytes[1] & 0x80 != 0 else {
            throw PKCS15ParsingError.invalidRecord
        }
        return try bytes.reduce(0) { value, byte in
            guard value <= Int.max >> 8 else {
                throw PKCS15ParsingError.invalidRecord
            }
            return value << 8 | Int(byte)
        }
    }
}
