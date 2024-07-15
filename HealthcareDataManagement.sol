// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Importing OpenZeppelin's access control contracts
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

// Smart contract for managing healthcare data securely using blockchain technology
contract HealthcareDataManagement is AccessControl, Ownable {
    // Define a role identifier for healthcare providers
    bytes32 public constant HEALTHCARE_PROVIDER_ROLE = keccak256("HEALTHCARE_PROVIDER_ROLE");

    // Struct to represent a medical record
    struct Record {
        uint256 id;         // Unique identifier for the record
        string dataHash;    // Hash of the medical data (stored off-chain)
        address owner;      // Owner of the record
        bool exists;        // Flag to check if the record exists
    }

    // Struct to log access to records
    struct AccessLog {
        uint256 recordId;   // ID of the accessed record
        address accessedBy; // Address of the user who accessed the record
        uint256 timestamp;  // Timestamp of when the access occurred
    }

    // Mappings to store records and access permissions
    mapping(uint256 => Record) private records;                     // Map record ID to Record struct
    mapping(address => uint256[]) private ownerRecords;             // Map owner address to their records
    mapping(address => mapping(uint256 => bool)) private accessControl; // Map address to record access permissions
    AccessLog[] private accessLogs;                                 // Array to store access logs
    uint256 private nextRecordId;                                   // Counter for record IDs

    // Events to log significant actions
    event RecordCreated(uint256 id, address owner);                // Event when a record is created
    event AccessGranted(uint256 id, address to);                   // Event when access is granted to a record
    event AccessRevoked(uint256 id, address from);                 // Event when access is revoked from a record
    event RecordAccessed(uint256 id, address by);                  // Event when a record is accessed

    // Constructor to set up default roles and ownership
    constructor(address admin) Ownable(admin) {
        _setupDefaultRoles(admin); // Initialize roles with the provided admin address
    }
