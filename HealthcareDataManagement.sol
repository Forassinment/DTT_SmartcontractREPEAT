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
 // Internal function to set up default roles
    function _setupDefaultRoles(address admin) internal {
        _setupRole(DEFAULT_ADMIN_ROLE, admin); // Grant admin role
        _setupRole(HEALTHCARE_PROVIDER_ROLE, admin); // Grant healthcare provider role
    }

    // Internal function to set up roles
    function _setupRole(bytes32 role, address account) internal {
        grantRole(role, account); // Grant specified role to account
    }

    // Modifier to allow only the owner or a healthcare provider to execute a function
    modifier onlyOwnerOrProvider() {
        require(
            hasRole(HEALTHCARE_PROVIDER_ROLE, msg.sender) || owner() == msg.sender,
            "Only owner or healthcare provider can perform this action"
        );
        _;
    }

    // Function to create a new medical record
    function createRecord(string memory dataHash) public {
        uint256 recordId = nextRecordId++; // Generate a new record ID
        records[recordId] = Record(recordId, dataHash, msg.sender, true); // Store the new record
        ownerRecords[msg.sender].push(recordId); // Link the record to the owner
        emit RecordCreated(recordId, msg.sender); // Emit event for record creation
    }

    // Function to grant access to a specific record
    function grantAccess(uint256 recordId, address to) public {
        require(records[recordId].exists, "Record does not exist"); // Ensure the record exists
        require(records[recordId].owner == msg.sender, "Only owner can grant access"); // Ensure the sender is the owner
        accessControl[to][recordId] = true; // Grant access
        emit AccessGranted(recordId, to); // Emit event for access granted
    }

    // Function to revoke access from a specific record
    function revokeAccess(uint256 recordId, address from) public {
        require(records[recordId].exists, "Record does not exist"); // Ensure the record exists
        require(records[recordId].owner == msg.sender, "Only owner can revoke access"); // Ensure the sender is the owner
        accessControl[from][recordId] = false; // Revoke access
        emit AccessRevoked(recordId, from); // Emit event for access revoked
    }

    // Function to get the data of a record, only accessible by the owner or healthcare providers
    function getRecord(uint256 recordId) public onlyOwnerOrProvider returns (string memory) {
        require(records[recordId].exists, "Record does not exist"); // Ensure the record exists
        require(
            accessControl[msg.sender][recordId] || records[recordId].owner == msg.sender,
            "Access denied"
        ); // Ensure the caller has access permissions

        // Log the access
        accessLogs.push(AccessLog(recordId, msg.sender, block.timestamp)); // Record the access event
        emit RecordAccessed(recordId, msg.sender); // Emit event for record access