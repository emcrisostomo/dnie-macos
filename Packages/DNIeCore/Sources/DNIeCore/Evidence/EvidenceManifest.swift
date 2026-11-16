import Foundation

/// A validated, immutable bridge from canonical evidence records to profile capabilities.
/// The JSON shape is Validation/evidence-schema.json; version and mapping are explicit inputs.
public struct EvidenceManifest: Sendable {
    public enum LoadError: Error, Equatable {
        case unsupportedVersion
        case oversizedInput
        case malformedRecords
        case duplicateEvidenceID
        case invalidMapping
    }

    public let version: String
    public let capabilityGate: CapabilityGate

    private init(version: String, capabilityGate: CapabilityGate) {
        self.version = version
        self.capabilityGate = capabilityGate
    }

    public static func load(
        version: String,
        evidenceRecords: Data,
        capabilityEvidenceIDs: [ProfileCapability: [String]]
    ) throws -> EvidenceManifest {
        guard version == "1" else { throw LoadError.unsupportedVersion }
        guard !evidenceRecords.isEmpty, evidenceRecords.count <= 262_144 else {
            throw LoadError.oversizedInput
        }
        guard let raw = try? JSONSerialization.jsonObject(with: evidenceRecords),
              let records = raw as? [[String: Any]],
              !records.isEmpty, records.count <= 256,
              !hasDuplicateObjectKeys(evidenceRecords) else {
            throw LoadError.malformedRecords
        }

        var states: [String: EvidenceState] = [:]
        for record in records {
            let (id, state) = try validate(record)
            guard states.updateValue(state, forKey: id) == nil else {
                throw LoadError.duplicateEvidenceID
            }
        }

        var requirements: [ProfileCapability: [EvidenceRequirement]] = [:]
        for (capability, ids) in capabilityEvidenceIDs {
            guard !ids.isEmpty, ids.count <= 256, Set(ids).count == ids.count else {
                throw LoadError.invalidMapping
            }
            requirements[capability] = try ids.map { id in
                guard let state = states[id] else { throw LoadError.invalidMapping }
                return EvidenceRequirement(evidenceID: id, state: state)
            }
        }
        return EvidenceManifest(version: version, capabilityGate: CapabilityGate(requirements: requirements))
    }

    private static func validate(_ record: [String: Any]) throws -> (String, EvidenceState) {
        let allowed: Set<String> = [
            "evidence_id", "claim", "state", "primary_source", "experiment_id",
            "supporting_evidence", "decision_impact", "review_date",
        ]
        guard Set(record.keys).isSubset(of: allowed),
              let id = record["evidence_id"] as? String,
              matchesEntire(id, #"E-[A-Z0-9][A-Z0-9._-]{2,63}"#),
              let claim = boundedString(record["claim"], max: 1000),
              let impact = boundedString(record["decision_impact"], max: 1000),
              !claim.isEmpty, !impact.isEmpty,
              let stateName = record["state"] as? String,
              let state = EvidenceState(rawValue: stateName),
              let date = record["review_date"] as? String,
              validDate(date) else {
            throw LoadError.malformedRecords
        }

        if let source = record["primary_source"] {
            guard let pointer = boundedString(source, max: 512), validPointer(pointer) else {
                throw LoadError.malformedRecords
            }
        } else if state == .documented {
            throw LoadError.malformedRecords
        }
        if let experiment = record["experiment_id"] {
            guard let value = experiment as? String,
                  matchesEntire(value, #"[A-Z][A-Z0-9._-]{1,63}"#) else {
                throw LoadError.malformedRecords
            }
        } else if state == .experimentallyVerified {
            throw LoadError.malformedRecords
        }
        if let supporting = record["supporting_evidence"] {
            guard let pointers = supporting as? [String], !pointers.isEmpty,
                  pointers.count <= 256, Set(pointers).count == pointers.count,
                  pointers.allSatisfy(validPointer) else {
                throw LoadError.malformedRecords
            }
        } else if state == .inferred {
            throw LoadError.malformedRecords
        }
        return (id, state)
    }

    private static func boundedString(_ value: Any?, max: Int) -> String? {
        guard let string = value as? String,
              !string.isEmpty, string.unicodeScalars.count <= max else { return nil }
        return string
    }

    private static func validPointer(_ value: String) -> Bool {
        guard !value.isEmpty, value.unicodeScalars.count <= 512 else { return false }
        let forbidden = #"PIN|password|chip[ _-]?serial|CKA_ID|raw[ _-]?APDU|session[ _-]?key|private[ _-]?(key|exponent)|credential[ _-]?bytes"#
        return value.range(of: forbidden, options: [.regularExpression, .caseInsensitive]) == nil
    }

    private static func validDate(_ value: String) -> Bool {
        guard matchesEntire(value, #"[0-9]{4}-[0-9]{2}-[0-9]{2}"#) else {
            return false
        }
        let parts = value.split(separator: "-").compactMap { Int($0) }
        guard parts.count == 3, parts[0] > 0 else { return false }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        let components = DateComponents(year: parts[0], month: parts[1], day: parts[2])
        guard let date = calendar.date(from: components) else { return false }
        let roundTrip = calendar.dateComponents([.year, .month, .day], from: date)
        return roundTrip.year == parts[0] && roundTrip.month == parts[1] && roundTrip.day == parts[2]
    }

    private static func matchesEntire(_ value: String, _ body: String) -> Bool {
        guard let range = value.range(of: "^(?:\(body))$", options: .regularExpression) else {
            return false
        }
        return range.lowerBound == value.startIndex && range.upperBound == value.endIndex
    }

    /// JSONSerialization accepts repeated object members. Reject those before trusting its map.
    /// JSONSerialization has already checked JSON grammar; this pass tracks object keys only.
    private static func hasDuplicateObjectKeys(_ data: Data) -> Bool {
        struct Frame {
            let isObject: Bool
            var expectsKey: Bool
            var keys: Set<String> = []
        }
        let bytes = [UInt8](data)
        var frames: [Frame] = []
        var index = 0
        while index < bytes.count {
            switch bytes[index] {
            case 0x7B: // {
                frames.append(Frame(isObject: true, expectsKey: true))
            case 0x5B: // [
                frames.append(Frame(isObject: false, expectsKey: false))
            case 0x7D, 0x5D: // } or ]
                if !frames.isEmpty { frames.removeLast() }
            case 0x2C: // ,
                if !frames.isEmpty && frames[frames.count - 1].isObject {
                    frames[frames.count - 1].expectsKey = true
                }
            case 0x22: // "
                let start = index
                index += 1
                while index < bytes.count {
                    if bytes[index] == 0x5C { index += 2; continue }
                    if bytes[index] == 0x22 { break }
                    index += 1
                }
                if !frames.isEmpty && frames[frames.count - 1].isObject
                    && frames[frames.count - 1].expectsKey {
                    let quoted = Data(bytes[start...index])
                    guard let key = try? JSONDecoder().decode(String.self, from: quoted) else {
                        return true
                    }
                    if !frames[frames.count - 1].keys.insert(key).inserted { return true }
                    frames[frames.count - 1].expectsKey = false
                }
            default:
                break
            }
            index += 1
        }
        return false
    }
}
