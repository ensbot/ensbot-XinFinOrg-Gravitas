/*
 * This code has not been reviewed.
 * Do not use or deploy this code before reviewing it personally first.
 */
pragma solidity ^0.5.0;



import "./IERC1400.sol";
import "./token/ERC1400Partition/ERC1400Partition.sol";


/**
 * @title ERC1400
 * @dev ERC1400 logic
 */
contract ERC1400 is IERC1400, ERC1400Partition, MinterRole {

  struct Doc {
    string docURI;
    bytes32 docHash;
  }

  // Mapping for token URIs.
  mapping(bytes32 => Doc) internal _documents;

  // Indicate whether the token can still be issued by the issuer or not anymore.
  bool internal _isIssuable;

  /**
   * @dev Modifier to verify if token is issuable.
   */
  modifier issuableToken() {
    require(_isIssuable, "A8"); // Transfer Blocked - Token restriction
    _;
  }

  /**
   * [ERC1400 CONSTRUCTOR]
   * @dev Initialize ERC1400 + register
   * the contract implementation in ERC1820Registry.
   * @param name Name of the token.
   * @param symbol Symbol of the token.
   * @param granularity Granularity of the token.
   * @param controllers Array of initial controllers.
   * @param certificateSigner Address of the off-chain service which signs the
   * conditional ownership certificates required for token transfers, issuance,
   * redemption (Cf. CertificateController.sol).
   */
  constructor(
    string memory name,
    string memory symbol,
    uint256 granularity,
    address[] memory controllers,
    address certificateSigner,
    bytes32[] memory defaultPartitions
  )
    public
    ERC1400Partition(name, symbol, granularity, controllers, certificateSigner, defaultPartitions)
  {
    setInterfaceImplementation("ERC1400Token", address(this));
    _isControllable = true;
    _isIssuable = true;
  }

  /********************** ERC1400 EXTERNAL FUNCTIONS **************************/

  /**
   * [ERC1400 INTERFACE (1/9)]
   * @dev Access a document associated with the token.
   * @param name Short name (represented as a bytes32) associated to the document.
   * @return Requested document + document hash.
   */
  function getDocument(bytes32 name) external view returns (string memory, bytes32) {
    require(bytes(_documents[name].docURI).length != 0); // Action Blocked - Empty document
    return (
      _documents[name].docURI,
      _documents[name].docHash
    );
  }

  /**
   * [ERC1400 INTERFACE (2/9)]
   * @dev Associate a document with the token.
   * @param name Short name (represented as a bytes32) associated to the document.
   * @param uri Document content.
   * @param documentHash Hash of the document [optional parameter].
   */
  function setDocument(bytes32 name, string calldata uri, bytes32 documentHash) external {
    require(_isController[msg.sender]);
    _documents[name] = Doc({
      docURI: uri,
      docHash: documentHash
    });
    emit Document(name, uri, documentHash);
  }

  /**
   * [ERC1400 INTERFACE (3/9)]
   * @dev Know if the token can be controlled by operators.
   * If a token returns 'false' for 'isControllable()'' then it MUST always return 'false' in the future.
   * @return bool 'true' if the token can still be controlled by operators, 'false' if it can't anymore.
   */
  function isControllable() external view returns (bool) {
    return _isControllable;
  }

  /**
   * [ERC1400 INTERFACE (4/9)]
   * @dev Know if new tokens can be issued in the future.
   * @return bool 'true' if tokens can still be issued by the issuer, 'false' if they can't anymore.
   */
  function isIssuable() external view returns (bool) {
    return _isIssuable;
  }

  /**
   * [ERC1400 INTERFACE (5/9)]
   * @dev Issue tokens from a specific partition.
   * @param partition Name of the partition.
   * @param tokenHolder Address for which we want to issue tokens.
   * @param value Number of tokens issued.
   * @param data Information attached to the issuance, by the issuer. [CONTAINS THE CONDITIONAL OWNERSHIP CERTIFICATE]
   */
  function issueByPartition(bytes32 partition, address tokenHolder, uint256 value, bytes calldata data)
    external
    onlyMinter
    issuableToken
    isValidCertificate(data)
  {
    _issueByPartition(partition, msg.sender, tokenHolder, value, data, "");
  }

  /**
   * [ERC1400 INTERFACE (6/9)]
   * @dev Redeem tokens of a specific partition.
   * @param partition Name of the partition.
   * @param value Number of tokens redeemed.
   * @param data Information attached to the redemption, by the redeemer. [CONTAINS THE CONDITIONAL OWNERSHIP CERTIFICATE]
   */
  function redeemByPartition(bytes32 partition, uint256 value, bytes calldata data)
    external
    isValidCertificate(data)
  {
    _redeemByPartition(partition, msg.sender, msg.sender, value, data, "");
  }

  /**
   * [ERC1400 INTERFACE (7/9)]
   * @dev Redeem tokens of a specific partition.
   * @param partition Name of the partition.
   * @param tokenHolder Address for which we want to redeem tokens.
   * @param value Number of tokens redeemed.
   * @param data Information attached to the redemption.
   * @param operatorData Information attached to the redemption, by the operator. [CONTAINS THE CONDITIONAL OWNERSHIP CERTIFICATE]
   */
  function operatorRedeemByPartition(bytes32 partition, address tokenHolder, uint256 value, bytes calldata data, bytes calldata operatorData)
    external
    isValidCertificate(operatorData)
  {
    require(_isOperatorForPartition(partition, msg.sender, tokenHolder), "A7"); // Transfer Blocked - Identity restriction

    _redeemByPartition(partition, msg.sender, tokenHolder, value, data, operatorData);
  }

  /**
   * [ERC1400 INTERFACE (8/9)]
   * @dev Know the reason on success or failure based on the EIP-1066 application-specific status codes.
   * @param partition Name of the partition.
   * @param to Token recipient.
   * @param value Number of tokens to transfer.
   * @param data Information attached to the transfer, by the token holder. [CONTAINS THE CONDITIONAL OWNERSHIP CERTIFICATE]
   * @return ESC (Ethereum Status Code) following the EIP-1066 standard.
   * @return Additional bytes32 parameter that can be used to define
   * application specific reason codes with additional details (for example the
   * transfer restriction rule responsible for making the transfer operation invalid).
   * @return Destination partition.
   */
  function canTransferByPartition(bytes32 partition, address to, uint256 value, bytes calldata data)
    external
    view
    returns (byte, bytes32, bytes32)
  {
    if(!_checkCertificate(data, 0, this.transferByPartition.selector)) { // 0xf3d490db: 4 first bytes of keccak256(transferByPartition(bytes32,address,uint256,bytes))
      return(hex"A3", "", partition); // Transfer Blocked - Sender lockup period not ended
    } else {
      return _canTransfer(partition, msg.sender, msg.sender, to, value, data, "");
    }
  }

  /**
   * [ERC1400 INTERFACE (9/9)]
   * @dev Know the reason on success or failure based on the EIP-1066 application-specific status codes.
   * @param partition Name of the partition.
   * @param from Token holder.
   * @param to Token recipient.
   * @param value Number of tokens to transfer.
   * @param data Information attached to the transfer. [CAN CONTAIN THE DESTINATION PARTITION]
   * @param operatorData Information attached to the transfer, by the operator. [CONTAINS THE CONDITIONAL OWNERSHIP CERTIFICATE]
   * @return ESC (Ethereum Status Code) following the EIP-1066 standard.
   * @return Additional bytes32 parameter that can be used to define
   * application specific reason codes with additional details (for example the
   * transfer restriction rule responsible for making the transfer operation invalid).
   * @return Destination partition.
   */
  function canOperatorTransferByPartition(bytes32 partition, address from, address to, uint256 value, bytes calldata data, bytes calldata operatorData)
    external
    view
    returns (byte, bytes32, bytes32)
  {
    if(!_checkCertificate(operatorData, 0, this.operatorTransferByPartition.selector)) { // 0x8c0dee9c: 4 first bytes of keccak256(operatorTransferByPartition(bytes32,address,address,uint256,bytes,bytes))
      return(hex"A3", "", partition); // Transfer Blocked - Sender lockup period not ended
    } else {
      return _canTransfer(partition, msg.sender, from, to, value, data, operatorData);
    }
  }

  /********************** ERC1400 INTERNAL FUNCTIONS **************************/

  /**
   * [INTERNAL]
   * @dev Know the reason on success or failure based on the EIP-1066 application-specific status codes.
   * @param partition Name of the partition.
   * @param operator The address performing the transfer.
   * @param from Token holder.
   * @param to Token recipient.
   * @param value Number of tokens to transfer.
   * @param data Information attached to the transfer. [CAN CONTAIN THE DESTINATION PARTITION]
   * @param operatorData Information attached to the transfer, by the operator (if any).
   * @return ESC (Ethereum Status Code) following the EIP-1066 standard.
   * @return Additional bytes32 parameter that can be used to define
   * application specific reason codes with additional details (for example the
   * transfer restriction rule responsible for making the transfer operation invalid).
   * @return Destination partition.
   */
   function _canTransfer(bytes32 partition, address operator, address from, address to, uint256 value, bytes memory data, bytes memory operatorData)
     internal
     view
     returns (byte, bytes32, bytes32)
   {
     if(!_isOperatorForPartition(partition, operator, from))
       return(hex"A7", "", partition); // "Transfer Blocked - Identity restriction"

     if((_balances[from] < value) || (_balanceOfByPartition[from][partition] < value))
       return(hex"A4", "", partition); // Transfer Blocked - Sender balance insufficient

     if(to == address(0))
       return(hex"A6", "", partition); // Transfer Blocked - Receiver not eligible

     address senderImplementation;
     address recipientImplementation;
     senderImplementation = interfaceAddr(from, "ERC1400TokensSender");
     recipientImplementation = interfaceAddr(to, "ERC1400TokensRecipient");

     if((senderImplementation != address(0))
       && !IERC1400TokensSender(senderImplementation).canTransfer(partition, from, to, value, data, operatorData))
       return(hex"A5", "", partition); // Transfer Blocked - Sender not eligible

     if((recipientImplementation != address(0))
       && !IERC1400TokensRecipient(recipientImplementation).canReceive(partition, from, to, value, data, operatorData))
       return(hex"A6", "", partition); // Transfer Blocked - Receiver not eligible

     if(!_isMultiple(value))
       return(hex"A9", "", partition); // Transfer Blocked - Token granularity

     return(hex"A2", "", partition);  // Transfer Verified - Off-Chain approval for restricted token
   }

  /**
   * [INTERNAL]
   * @dev Issue tokens from a specific partition.
   * @param toPartition Name of the partition.
   * @param operator The address performing the issuance.
   * @param to Token recipient.
   * @param value Number of tokens to issue.
   * @param data Information attached to the issuance.
   * @param operatorData Information attached to the issuance, by the operator (if any).
   */
  function _issueByPartition(
    bytes32 toPartition,
    address operator,
    address to,
    uint256 value,
    bytes memory data,
    bytes memory operatorData
  )
    internal
  {
    _issue(toPartition, operator, to, value, data, operatorData);
    _addTokenToPartition(to, toPartition, value);

    emit IssuedByPartition(toPartition, operator, to, value, data, operatorData);
  }

  /**
   * [INTERNAL]
   * @dev Redeem tokens of a specific partition.
   * @param fromPartition Name of the partition.
   * @param operator The address performing the redemption.
   * @param from Token holder whose tokens will be redeemed.
   * @param value Number of tokens to redeem.
   * @param data Information attached to the redemption.
   * @param operatorData Information attached to the redemption, by the operator (if any).
   */
  function _redeemByPartition(
    bytes32 fromPartition,
    address operator,
    address from,
    uint256 value,
    bytes memory data,
    bytes memory operatorData
  )
    internal
  {
    require(_balanceOfByPartition[from][fromPartition] >= value, "A4"); // Transfer Blocked - Sender balance insufficient

    _removeTokenFromPartition(from, fromPartition, value);
    _redeem(fromPartition, operator, from, value, data, operatorData);

    emit RedeemedByPartition(fromPartition, operator, from, value, data, operatorData);
  }

  /********************** ERC1400 OPTIONAL FUNCTIONS **************************/

  /**
   * [NOT MANDATORY FOR ERC1400 STANDARD]
   * @dev Definitely renounce the possibility to control tokens on behalf of tokenHolders.
   * Once set to false, '_isControllable' can never be set to 'true' again.
   */
  function renounceControl() external onlyOwner {
    _isControllable = false;
  }

  /**
   * [NOT MANDATORY FOR ERC1400 STANDARD]
   * @dev Definitely renounce the possibility to issue new tokens.
   * Once set to false, '_isIssuable' can never be set to 'true' again.
   */
  function renounceIssuance() external onlyOwner {
    _isIssuable = false;
  }

  /**
   * [NOT MANDATORY FOR ERC1400 STANDARD]
   * @dev Set list of token controllers.
   * @param operators Controller addresses.
   */
  function setControllers(address[] calldata operators) external onlyOwner {
    _setControllers(operators);
  }

  /**
   * [NOT MANDATORY FOR ERC1400 STANDARD]
   * @dev Set list of token partition controllers.
   * @param partition Name of the partition.
   * @param operators Controller addresses.
   */
   function setPartitionControllers(bytes32 partition, address[] calldata operators) external onlyOwner {
     _setPartitionControllers(partition, operators);
   }

   /**
   * @dev Add a certificate signer for the token.
   * @param operator Address to set as a certificate signer.
   * @param authorized 'true' if operator shall be accepted as certificate signer, 'false' if not.
   */
  function setCertificateSigner(address operator, bool authorized) external onlyOwner {
    _setCertificateSigner(operator, authorized);
  }

  /************* ERC1400Partition/ERC1400Raw BACKWARDS RETROCOMPATIBILITY ******************/


  /**
   * [NOT MANDATORY FOR ERC1400 STANDARD][OVERRIDES ERC1400Partition METHOD]
   * @dev Redeem the value of tokens from the address 'msg.sender'.
   * @param value Number of tokens to redeem.
   * @param data Information attached to the redemption, by the token holder. [CONTAINS THE CONDITIONAL OWNERSHIP CERTIFICATE]
   */
  function redeem(uint256 value, bytes calldata data)
    external
    isValidCertificate(data)
  {
    _redeemByDefaultPartitions(msg.sender, msg.sender, value, data, "");
  }

  /**
   * [NOT MANDATORY FOR ERC1400 STANDARD][OVERRIDES ERC1400Partition METHOD]
   * @dev Redeem the value of tokens on behalf of the address 'from'.
   * @param from Token holder whose tokens will be redeemed (or 'address(0)' to set from to 'msg.sender').
   * @param value Number of tokens to redeem.
   * @param data Information attached to the redemption.
   * @param operatorData Information attached to the redemption, by the operator. [CONTAINS THE CONDITIONAL OWNERSHIP CERTIFICATE]
   */
  function redeemFrom(address from, uint256 value, bytes calldata data, bytes calldata operatorData)
    external
    isValidCertificate(operatorData)
  {
    require(_isOperator(msg.sender, from), "A7"); // Transfer Blocked - Identity restriction

    _redeemByDefaultPartitions(msg.sender, from, value, data, operatorData);
  }

  /**
  * [NOT MANDATORY FOR ERC1400Partition STANDARD]
   * @dev Redeem tokens from a default partitions.
   * @param operator The address performing the redeem.
   * @param from Token holder.
   * @param value Number of tokens to redeem.
   * @param data Information attached to the redemption.
   * @param operatorData Information attached to the redemption, by the operator (if any).
   */
  function _redeemByDefaultPartitions(
    address operator,
    address from,
    uint256 value,
    bytes memory data,
    bytes memory operatorData
  )
    internal
  {
    require(_defaultPartitions.length != 0, "A8"); // Transfer Blocked - Token restriction

    uint256 _remainingValue = value;
    uint256 _localBalance;

    for (uint i = 0; i < _defaultPartitions.length; i++) {
      _localBalance = _balanceOfByPartition[from][_defaultPartitions[i]];
      if(_remainingValue <= _localBalance) {
        _redeemByPartition(_defaultPartitions[i], operator, from, _remainingValue, data, operatorData);
        _remainingValue = 0;
        break;
      } else {
        _redeemByPartition(_defaultPartitions[i], operator, from, _localBalance, data, operatorData);
        _remainingValue = _remainingValue - _localBalance;
      }
    }

    require(_remainingValue == 0, "A8"); // Transfer Blocked - Token restriction
  }

}


/**
 * @title ERC1400 security token standard
 * @dev ERC1400 logic
 */
interface IERC1400  {

    // Document Management
    function getDocument(bytes32 name) external view returns (string memory, bytes32); // 1/9
    function setDocument(bytes32 name, string calldata uri, bytes32 documentHash) external; // 2/9
    event Document(bytes32 indexed name, string uri, bytes32 documentHash);

    // Controller Operation
    function isControllable() external view returns (bool); // 3/9

    // Token Issuance
    function isIssuable() external view returns (bool); // 4/9
    function issueByPartition(bytes32 partition, address tokenHolder, uint256 value, bytes calldata data) external; // 5/9
    event IssuedByPartition(bytes32 indexed partition, address indexed operator, address indexed to, uint256 value, bytes data, bytes operatorData);

    // Token Redemption
    function redeemByPartition(bytes32 partition, uint256 value, bytes calldata data) external; // 6/9
    function operatorRedeemByPartition(bytes32 partition, address tokenHolder, uint256 value, bytes calldata data, bytes calldata operatorData) external; // 7/9
    event RedeemedByPartition(bytes32 indexed partition, address indexed operator, address indexed from, uint256 value, bytes data, bytes operatorData);

    // Transfer Validity
    function canTransferByPartition(bytes32 partition, address to, uint256 value, bytes calldata data) external view returns (byte, bytes32, bytes32); // 8/9
    function canOperatorTransferByPartition(bytes32 partition, address from, address to, uint256 value, bytes calldata data, bytes calldata operatorData) external view returns (byte, bytes32, bytes32); // 9/9

}

/**
 * Reason codes - ERC1066
 *
 * To improve the token holder experience, canTransfer MUST return a reason byte code
 * on success or failure based on the EIP-1066 application-specific status codes specified below.
 * An implementation can also return arbitrary data as a bytes32 to provide additional
 * information not captured by the reason code.
 *
 * Code	Reason
 * 0xA0	Transfer Verified - Unrestricted
 * 0xA1	Transfer Verified - On-Chain approval for restricted token
 * 0xA2	Transfer Verified - Off-Chain approval for restricted token
 * 0xA3	Transfer Blocked - Sender lockup period not ended
 * 0xA4	Transfer Blocked - Sender balance insufficient
 * 0xA5	Transfer Blocked - Sender not eligible
 * 0xA6	Transfer Blocked - Receiver not eligible
 * 0xA7	Transfer Blocked - Identity restriction
 * 0xA8	Transfer Blocked - Token restriction
 * 0xA9	Transfer Blocked - Token granularity
 */


contract CertificateController is CertificateControllerMock {

  constructor(address _certificateSigner) public CertificateControllerMock(_certificateSigner) {}

}
pragma solidity ^0.5.0;


contract CertificateControllerMock {

  // Address used by off-chain controller service to sign certificate
  mapping(address => bool) internal _certificateSigners;

  // A nonce used to ensure a certificate can be used only once
  mapping(address => uint256) internal _checkCount;

  event Checked(address sender);

  constructor(address _certificateSigner) public {
    _setCertificateSigner(_certificateSigner, true);
  }

  /**
   * @dev Modifier to protect methods with certificate control
   */
  modifier isValidCertificate(bytes memory data) {

    require(_certificateSigners[msg.sender] || _checkCertificate(data, 0, 0x00000000), "A3"); // Transfer Blocked - Sender lockup period not ended

    _checkCount[msg.sender] += 1; // Increment sender check count

    emit Checked(msg.sender);
    _;
  }

  /**
   * @dev Get number of transations already sent to this contract by the sender
   * @param sender Address whom to check the counter of.
   * @return uint256 Number of transaction already sent to this contract.
   */
  function checkCount(address sender) external view returns (uint256) {
    return _checkCount[sender];
  }

  /**
   * @dev Get certificate signer authorization for an operator.
   * @param operator Address whom to check the certificate signer authorization for.
   * @return bool 'true' if operator is authorized as certificate signer, 'false' if not.
   */
  function certificateSigners(address operator) external view returns (bool) {
    return _certificateSigners[operator];
  }

  /**
   * @dev Set signer authorization for operator.
   * @param operator Address to add/remove as a certificate signer.
   * @param authorized 'true' if operator shall be accepted as certificate signer, 'false' if not.
   */
  function _setCertificateSigner(address operator, bool authorized) internal {
    require(operator != address(0)); // Action Blocked - Not a valid address
    _certificateSigners[operator] = authorized;
  }

  /**
   * @dev Checks if a certificate is correct
   * @param data Certificate to control
   */
   function _checkCertificate(bytes memory data, uint256 /*value*/, bytes4 /*functionID*/) internal pure returns(bool) { // Comments to avoid compilation warnings for unused variables.
     if(data.length > 0 && (data[0] == hex"10" || data[0] == hex"11" || data[0] == hex"22")) {
       return true;
     } else {
       return false;
     }
   }
}

pragma solidity ^0.5.0;
import "../token/ERC1400Partition/ERC1400Partition.sol";


contract ERC1400PartitionMock is ERC1400Partition {

  constructor(
    string memory name,
    string memory symbol,
    uint256 granularity,
    address[] memory controllers,
    address certificateSigner,
    bytes32[] memory tokenDefaultPartitions,
    address tokenHolderMock,
    uint256 valueMock
  )
    public
    ERC1400Partition(name, symbol, granularity, controllers, certificateSigner, tokenDefaultPartitions)
  {
    _issue("", msg.sender, tokenHolderMock, valueMock, "", "");
  }

}

pragma solidity ^0.5.0;
import "../token/ERC1400Raw/ERC1400RawIssuable.sol";


contract ERC1400RawMock is ERC1400RawIssuable {

  constructor(
    string memory name,
    string memory symbol,
    uint256 granularity,
    address[] memory controllers,
    address certificateSigner
  )
    public
    ERC1400Raw(name, symbol, granularity, controllers, certificateSigner)
  {
  }

  function setControllable(bool _controllable) external onlyOwner {
    _isControllable = _controllable;
  }

  function renounceControl() external onlyOwner {
    _isControllable = false;
  }

  function setControllers(address[] calldata operators) external onlyOwner {
    _setControllers(operators);
  }

  function isRegularAddress(address adr) external view returns(bool) {
    return _isRegularAddress(adr);
  }

  function redeemFromMock(address from, uint256 value, bytes calldata data, bytes calldata operatorData) external {
    _redeem("", msg.sender, from, value, data, operatorData);
  }

}

pragma solidity ^0.5.0;

import "../token/ERC1400Raw/IERC1400TokensRecipient.sol";
import "./ERC1820ImplementerMock.sol";


contract ERC1400TokensRecipientMock is IERC1400TokensRecipient, ERC1820ImplementerMock {

  constructor(string memory interfaceLabel)
    public
    ERC1820ImplementerMock(interfaceLabel)
  {

  }

  function canReceive(
    bytes32 /*partition*/,
    address from,
    address to,
    uint value,
    bytes calldata data,
    bytes calldata /*operatorData*/
  ) // Comments to avoid compilation warnings for unused variables.
    external
    view
    returns(bool)
  {
    return(_canReceive(from, to, value, data));
  }

  function tokensReceived(
    bytes32 /*partition*/,
    address /*operator*/,
    address from,
    address to,
    uint value,
    bytes calldata data,
    bytes calldata /*operatorData*/
  ) // Comments to avoid compilation warnings for unused variables.
    external
  {
    require(_canReceive(from, to, value, data), "A6"); // Transfer Blocked - Receiver not eligible
  }

  function _canReceive(
    address /*from*/,
    address /*to*/,
    uint /*value*/,
    bytes memory data
  ) // Comments to avoid compilation warnings for unused variables.
    internal
    pure
    returns(bool)
  {
    bytes32 receiveRevert = 0x2200000000000000000000000000000000000000000000000000000000000000; // Default recipient hook failure data for the mock only
    bytes32 data32;
    assembly {
        data32 := mload(add(data, 32))
    }
    if (data32 == receiveRevert) {
      return false;
    } else {
      return true;
    }
  }

}


pragma solidity ^0.5.0;

import "../token/ERC1400Raw/IERC1400TokensSender.sol";
import "./ERC1820ImplementerMock.sol";


contract ERC1400TokensSenderMock is IERC1400TokensSender, ERC1820ImplementerMock {

  constructor(string memory interfaceLabel)
    public
    ERC1820ImplementerMock(interfaceLabel)
  {

  }

  function canTransfer(
    bytes32 /*partition*/,
    address from,
    address to,
    uint value,
    bytes calldata data,
    bytes calldata /*operatorData*/
  ) // Comments to avoid compilation warnings for unused variables.
    external
    view
    returns(bool)
  {
    return(_canTransfer(from, to, value, data));
  }

  function tokensToTransfer(
    bytes32 /*partition*/,
    address /*operator*/,
    address from,
    address to,
    uint value,
    bytes calldata data,
    bytes calldata /*operatorData*/
  ) // Comments to avoid compilation warnings for unused variables.
    external
  {
    require(_canTransfer(from, to, value, data), "A5"); // Transfer Blocked - Sender not eligible
  }

  function _canTransfer(
    address /*from*/,
    address /*to*/,
    uint /*value*/,
    bytes memory data
  ) // Comments to avoid compilation warnings for unused variables.
    internal
    pure
    returns(bool)
  {
    bytes32 transferRevert = 0x1100000000000000000000000000000000000000000000000000000000000000; // Default sender hook failure data for the mock only
    bytes32 data32;
    assembly {
        data32 := mload(add(data, 32))
    }
    if (data32 == transferRevert) {
      return false;
    } else {
      return true;
    }
  }

}


pragma solidity ^0.5.0;


contract ERC1820Registry {
    function setInterfaceImplementer(address _addr, bytes32 _interfaceHash, address _implementer) external;
    function getInterfaceImplementer(address _addr, bytes32 _interfaceHash) external view returns (address);
    function setManager(address _addr, address _newManager) external;
    function getManager(address _addr) public view returns(address);
}


contract ERC1820ImplementerMock {
  bytes32 constant ERC1820_ACCEPT_MAGIC = keccak256(abi.encodePacked("ERC1820_ACCEPT_MAGIC"));

  ERC1820Registry constant ERC1820REGISTRY = ERC1820Registry(0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24);

  bytes32 internal _interfaceHash;

  constructor(string memory interfaceLabel) public {
    _interfaceHash = keccak256(abi.encodePacked(interfaceLabel));
  }

  function setERC1820Implementer() external {
    require(ERC1820REGISTRY.getManager(msg.sender) == address(this), "Manager rights neeed to be transferred to this contract first.");
    ERC1820REGISTRY.setInterfaceImplementer(msg.sender, _interfaceHash, address(this));
    ERC1820REGISTRY.setManager(msg.sender, msg.sender);
  }

  function canImplementInterfaceForAddress(bytes32 interfaceHash, address /*addr*/) // Comments to avoid compilation warnings for unused variables.
    external
    view
    returns(bytes32)
  {
    if(interfaceHash == _interfaceHash) {
      return ERC1820_ACCEPT_MAGIC;
    } else {
      return "";
    }
  }

}


/*
 * This code has not been reviewed.
 * Do not use or deploy this code before reviewing it personally first.
 */
pragma solidity ^0.5.0;

import "openzeppelin-solidity/contracts/token/ERC20/IERC20.sol";

import "../../ERC1400.sol";


/**
 * @title ERC1400ERC20
 * @dev ERC1400 with ERC20 retrocompatibility
 */
contract ERC1400ERC20 is IERC20, ERC1400 {

  // Mapping from (tokenHolder, spender) to allowed value.
  mapping (address => mapping (address => uint256)) internal _allowed;

  // Mapping from (tokenHolder) to whitelisted status.
  mapping (address => bool) internal _whitelisted;

  /**
   * @dev Modifier to verify if sender and recipient are whitelisted.
   */
  modifier areWhitelisted(address sender, address recipient) {
    require(_whitelisted[sender], "A5"); // Transfer Blocked - Sender not eligible
    require(_whitelisted[recipient], "A6"); // Transfer Blocked - Receiver not eligible
    _;
  }

  /**
   * [ERC1400ERC20 CONSTRUCTOR]
   * @dev Initialize ERC71400ERC20 and CertificateController parameters + register
   * the contract implementation in ERC1820Registry.
   * @param name Name of the token.
   * @param symbol Symbol of the token.
   * @param granularity Granularity of the token.
   * @param controllers Array of initial controllers.
   * @param certificateSigner Address of the off-chain service which signs the
   * conditional ownership certificates required for token transfers, issuance,
   * redemption (Cf. CertificateController.sol).
   */
  constructor(
    string memory name,
    string memory symbol,
    uint256 granularity,
    address[] memory controllers,
    address certificateSigner,
    bytes32[] memory tokenDefaultPartitions
  )
    public
    ERC1400(name, symbol, granularity, controllers, certificateSigner, tokenDefaultPartitions)
  {
    setInterfaceImplementation("ERC20Token", address(this));
  }

  /**
   * [OVERRIDES ERC1400 METHOD]
   * @dev Perform the transfer of tokens.
   * @param partition Name of the partition (bytes32 to be left empty for ERC1400Raw transfer).
   * @param operator The address performing the transfer.
   * @param from Token holder.
   * @param to Token recipient.
   * @param value Number of tokens to transfer.
   * @param data Information attached to the transfer.
   * @param operatorData Information attached to the transfer by the operator (if any).
   * @param preventLocking 'true' if you want this function to throw when tokens are sent to a contract not
   * implementing 'erc777tokenHolder'.
   * ERC1400Raw native transfer functions MUST set this parameter to 'true', and backwards compatible ERC20 transfer
   * functions SHOULD set this parameter to 'false'.
   */
  function _transferWithData(
    bytes32 partition,
    address operator,
    address from,
    address to,
    uint256 value,
    bytes memory data,
    bytes memory operatorData,
    bool preventLocking
  )
    internal
  {
    ERC1400Raw._transferWithData(partition, operator, from, to, value, data, operatorData, preventLocking);

    emit Transfer(from, to, value);
  }

  /**
   * [OVERRIDES ERC1400 METHOD]
   * @dev Perform the token redemption.
   * @param partition Name of the partition (bytes32 to be left empty for ERC1400Raw transfer).
   * @param operator The address performing the redemption.
   * @param from Token holder whose tokens will be redeemed.
   * @param value Number of tokens to redeem.
   * @param data Information attached to the redemption.
   * @param operatorData Information attached to the redemption by the operator (if any).
   */
  function _redeem(bytes32 partition, address operator, address from, uint256 value, bytes memory data, bytes memory operatorData) internal {
    ERC1400Raw._redeem(partition, operator, from, value, data, operatorData);

    emit Transfer(from, address(0), value);  //  ERC20 backwards compatibility
  }

  /**
   * [OVERRIDES ERC1400 METHOD]
   * @dev Perform the issuance of tokens.
   * @param partition Name of the partition (bytes32 to be left empty for ERC1400Raw transfer).
   * @param operator Address which triggered the issuance.
   * @param to Token recipient.
   * @param value Number of tokens issued.
   * @param data Information attached to the issuance.
   * @param operatorData Information attached to the issuance by the operator (if any).
   */
  function _issue(bytes32 partition, address operator, address to, uint256 value, bytes memory data, bytes memory operatorData) internal {
    ERC1400Raw._issue(partition, operator, to, value, data, operatorData);

    emit Transfer(address(0), to, value); // ERC20 backwards compatibility
  }

  /**
   * [OVERRIDES ERC1400 METHOD]
   * @dev Get the number of decimals of the token.
   * @return The number of decimals of the token. For Backwards compatibility, decimals are forced to 18 in ERC1400Raw.
   */
  function decimals() external pure returns(uint8) {
    return uint8(18);
  }

  /**
   * [NOT MANDATORY FOR ERC1400 STANDARD]
   * @dev Check the value of tokens that an owner allowed to a spender.
   * @param owner address The address which owns the funds.
   * @param spender address The address which will spend the funds.
   * @return A uint256 specifying the value of tokens still available for the spender.
   */
  function allowance(address owner, address spender) external view returns (uint256) {
    return _allowed[owner][spender];
  }

  /**
   * [NOT MANDATORY FOR ERC1400 STANDARD]
   * @dev Approve the passed address to spend the specified amount of tokens on behalf of 'msg.sender'.
   * Beware that changing an allowance with this method brings the risk that someone may use both the old
   * and the new allowance by unfortunate transaction ordering. One possible solution to mitigate this
   * race condition is to first reduce the spender's allowance to 0 and set the desired value afterwards:
   * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
   * @param spender The address which will spend the funds.
   * @param value The amount of tokens to be spent.
   * @return A boolean that indicates if the operation was successful.
   */
  function approve(address spender, uint256 value) external returns (bool) {
    require(spender != address(0), "A5"); // Transfer Blocked - Sender not eligible
    _allowed[msg.sender][spender] = value;
    emit Approval(msg.sender, spender, value);
    return true;
  }

  /**
   * [NOT MANDATORY FOR ERC1400 STANDARD]
   * @dev Transfer token for a specified address.
   * @param to The address to transfer to.
   * @param value The value to be transferred.
   * @return A boolean that indicates if the operation was successful.
   */
  function transfer(address to, uint256 value) external areWhitelisted(msg.sender, to) returns (bool) {
    _transferByDefaultPartitions(msg.sender, msg.sender, to, value, "", "", false);
    return true;
  }

  /**
   * [NOT MANDATORY FOR ERC1400 STANDARD]
   * @dev Transfer tokens from one address to another.
   * @param from The address which you want to transfer tokens from.
   * @param to The address which you want to transfer to.
   * @param value The amount of tokens to be transferred.
   * @return A boolean that indicates if the operation was successful.
   */
  function transferFrom(address from, address to, uint256 value) external areWhitelisted(from, to) returns (bool) {
    require( _isOperator(msg.sender, from)
      || (value <= _allowed[from][msg.sender]), "A7"); // Transfer Blocked - Identity restriction

    if(_allowed[from][msg.sender] >= value) {
      _allowed[from][msg.sender] = _allowed[from][msg.sender].sub(value);
    } else {
      _allowed[from][msg.sender] = 0;
    }

    _transferByDefaultPartitions(msg.sender, from, to, value, "", "", false);
    return true;
  }

  /***************** ERC1400ERC20 OPTIONAL FUNCTIONS ***************************/

  /**
   * [NOT MANDATORY FOR ERC1400ERC20 STANDARD]
   * @dev Get whitelisted status for a tokenHolder.
   * @param tokenHolder Address whom to check the whitelisted status for.
   * @return bool 'true' if tokenHolder is whitelisted, 'false' if not.
   */
  function whitelisted(address tokenHolder) external view returns (bool) {
    return _whitelisted[tokenHolder];
  }

  /**
   * [NOT MANDATORY FOR ERC1400ERC20 STANDARD]
   * @dev Set whitelisted status for a tokenHolder.
   * @param tokenHolder Address to add/remove from whitelist.
   * @param authorized 'true' if tokenHolder shall be added to whitelist, 'false' if not.
   */
  function setWhitelisted(address tokenHolder, bool authorized) external {
    require(_isController[msg.sender]);
    _setWhitelisted(tokenHolder, authorized);
  }

  /**
   * [NOT MANDATORY FOR ERC1400ERC20 STANDARD]
   * @dev Set whitelisted status for a tokenHolder.
   * @param tokenHolder Address to add/remove from whitelist.
   * @param authorized 'true' if tokenHolder shall be added to whitelist, 'false' if not.
   */
  function _setWhitelisted(address tokenHolder, bool authorized) internal {
    require(tokenHolder != address(0)); // Action Blocked - Not a valid address
    _whitelisted[tokenHolder] = authorized;
  }

}

/*
 * This code has not been reviewed.
 * Do not use or deploy this code before reviewing it personally first.
 */
pragma solidity ^0.5.0;

import "openzeppelin-solidity/contracts/token/ERC20/IERC20.sol";

import "../ERC1400Raw/ERC1400RawIssuable.sol";


/**
 * @title ERC1400RawERC20
 * @dev ERC1400Raw with ERC20 retrocompatibility
 */
contract ERC1400RawERC20 is IERC20, ERC1400RawIssuable {

  // Mapping from (tokenHolder, spender) to allowed value.
  mapping (address => mapping (address => uint256)) internal _allowed;

  // Mapping from (tokenHolder) to whitelisted status.
  mapping (address => bool) internal _whitelisted;

  /**
   * @dev Modifier to verify if sender and recipient are whitelisted.
   */
  modifier areWhitelisted(address sender, address recipient) {
    require(_whitelisted[sender], "A5"); // Transfer Blocked - Sender not eligible
    require(_whitelisted[recipient], "A6"); // Transfer Blocked - Receiver not eligible
    _;
  }

  /**
   * [ERC1400RawERC20 CONSTRUCTOR]
   * @dev Initialize ERC1400RawERC20 and CertificateController parameters + register
   * the contract implementation in ERC1820Registry.
   * @param name Name of the token.
   * @param symbol Symbol of the token.
   * @param granularity Granularity of the token.
   * @param controllers Array of initial controllers.
   * @param certificateSigner Address of the off-chain service which signs the
   * conditional ownership certificates required for token transfers, issuance,
   * redemption (Cf. CertificateController.sol).
   */
  constructor(
    string memory name,
    string memory symbol,
    uint256 granularity,
    address[] memory controllers,
    address certificateSigner
  )
    public
    ERC1400Raw(name, symbol, granularity, controllers, certificateSigner)
  {
    setInterfaceImplementation("ERC20Token", address(this));
  }

  /**
   * [OVERRIDES ERC1400Raw METHOD]
   * @dev Perform the transfer of tokens.
   * @param partition Name of the partition (bytes32 to be left empty for ERC1400Raw transfer).
   * @param operator The address performing the transfer.
   * @param from Token holder.
   * @param to Token recipient.
   * @param value Number of tokens to transfer.
   * @param data Information attached to the transfer.
   * @param operatorData Information attached to the transfer by the operator (if any).
   * @param preventLocking 'true' if you want this function to throw when tokens are sent to a contract not
   * implementing 'erc777tokenHolder'.
   * ERC1400Raw native transfer functions MUST set this parameter to 'true', and backwards compatible ERC20 transfer
   * functions SHOULD set this parameter to 'false'.
   */
  function _transferWithData(
    bytes32 partition,
    address operator,
    address from,
    address to,
    uint256 value,
    bytes memory data,
    bytes memory operatorData,
    bool preventLocking
  )
   internal
  {
    ERC1400Raw._transferWithData(partition, operator, from, to, value, data, operatorData, preventLocking);

    emit Transfer(from, to, value);
  }

  /**
   * [OVERRIDES ERC1400Raw METHOD]
   * @dev Perform the token redemption.
   * @param partition Name of the partition (bytes32 to be left empty for ERC1400Raw transfer).
   * @param operator The address performing the redemption.
   * @param from Token holder whose tokens will be redeemed.
   * @param value Number of tokens to redeem.
   * @param data Information attached to the redemption.
   * @param operatorData Information attached to the redemption by the operator (if any).
   */
  function _redeem(bytes32 partition, address operator, address from, uint256 value, bytes memory data, bytes memory operatorData) internal {
    ERC1400Raw._redeem(partition, operator, from, value, data, operatorData);

    emit Transfer(from, address(0), value);  //  ERC20 backwards compatibility
  }

  /**
   * [OVERRIDES ERC1400Raw METHOD]
   * @dev Perform the issuance of tokens.
   * @param partition Name of the partition (bytes32 to be left empty for ERC1400Raw transfer).
   * @param operator Address which triggered the issuance.
   * @param to Token recipient.
   * @param value Number of tokens issued.
   * @param data Information attached to the issuance.
   * @param operatorData Information attached to the issued by the operator (if any).
   */
  function _issue(bytes32 partition, address operator, address to, uint256 value, bytes memory data, bytes memory operatorData) internal {
    ERC1400Raw._issue(partition, operator, to, value, data, operatorData);

    emit Transfer(address(0), to, value); // ERC20 backwards compatibility
  }

  /**
   * [OVERRIDES ERC1400Raw METHOD]
   * @dev Get the number of decimals of the token.
   * @return The number of decimals of the token. For Backwards compatibility, decimals are forced to 18 in ERC1400Raw.
   */
  function decimals() external pure returns(uint8) {
    return uint8(18);
  }

  /**
   * [NOT MANDATORY FOR ERC1400Raw STANDARD]
   * @dev Check the amount of tokens that an owner allowed to a spender.
   * @param owner address The address which owns the funds.
   * @param spender address The address which will spend the funds.
   * @return A uint256 specifying the amount of tokens still available for the spender.
   */
  function allowance(address owner, address spender) external view returns (uint256) {
    return _allowed[owner][spender];
  }

  /**
   * [NOT MANDATORY FOR ERC1400Raw STANDARD]
   * @dev Approve the passed address to spend the specified amount of tokens on behalf of 'msg.sender'.
   * Beware that changing an allowance with this method brings the risk that someone may use both the old
   * and the new allowance by unfortunate transaction ordering. One possible solution to mitigate this
   * race condition is to first reduce the spender's allowance to 0 and set the desired value afterwards:
   * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
   * @param spender The address which will spend the funds.
   * @param value The amount of tokens to be spent.
   * @return A boolean that indicates if the operation was successful.
   */
  function approve(address spender, uint256 value) external returns (bool) {
    require(spender != address(0), "A5"); // Approval Blocked - Spender not eligible
    _allowed[msg.sender][spender] = value;
    emit Approval(msg.sender, spender, value);
    return true;
  }

  /**
   * [NOT MANDATORY FOR ERC1400Raw STANDARD]
   * @dev Transfer token for a specified address.
   * @param to The address to transfer to.
   * @param value The amount to be transferred.
   * @return A boolean that indicates if the operation was successful.
   */
  function transfer(address to, uint256 value) external areWhitelisted(msg.sender, to) returns (bool) {
    _transferWithData("", msg.sender, msg.sender, to, value, "", "", false);
    return true;
  }

  /**
   * [NOT MANDATORY FOR ERC1400Raw STANDARD]
   * @dev Transfer tokens from one address to another.
   * @param from The address which you want to transfer tokens from.
   * @param to The address which you want to transfer to.
   * @param value The amount of tokens to be transferred.
   * @return A boolean that indicates if the operation was successful.
   */
  function transferFrom(address from, address to, uint256 value) external areWhitelisted(from, to) returns (bool) {
    require( _isOperator(msg.sender, from)
      || (value <= _allowed[from][msg.sender]), "A7"); // Transfer Blocked - Identity restriction

    if(_allowed[from][msg.sender] >= value) {
      _allowed[from][msg.sender] = _allowed[from][msg.sender].sub(value);
    } else {
      _allowed[from][msg.sender] = 0;
    }

    _transferWithData("", msg.sender, from, to, value, "", "", false);
    return true;
  }

  /***************** ERC1400RawERC20 OPTIONAL FUNCTIONS ***************************/

  /**
   * [NOT MANDATORY FOR ERC1400RawERC20 STANDARD]
   * @dev Get whitelisted status for a tokenHolder.
   * @param tokenHolder Address whom to check the whitelisted status for.
   * @return bool 'true' if tokenHolder is whitelisted, 'false' if not.
   */
  function whitelisted(address tokenHolder) external view returns (bool) {
    return _whitelisted[tokenHolder];
  }

  /**
   * [NOT MANDATORY FOR ERC1400RawERC20 STANDARD]
   * @dev Set whitelisted status for a tokenHolder.
   * @param tokenHolder Address to add/remove from whitelist.
   * @param authorized 'true' if tokenHolder shall be added to whitelist, 'false' if not.
   */
  function setWhitelisted(address tokenHolder, bool authorized) external {
    require(_isController[msg.sender]);
    _setWhitelisted(tokenHolder, authorized);
  }

  /**
   * [NOT MANDATORY FOR ERC1400RawERC20 STANDARD]
   * @dev Set whitelisted status for a tokenHolder.
   * @param tokenHolder Address to add/remove from whitelist.
   * @param authorized 'true' if tokenHolder shall be added to whitelist, 'false' if not.
   */
  function _setWhitelisted(address tokenHolder, bool authorized) internal {
    require(tokenHolder != address(0)); // Action Blocked - Not a valid address
    _whitelisted[tokenHolder] = authorized;
  }

}

/*
 * This code has not been reviewed.
 * Do not use or deploy this code before reviewing it personally first.
 */
pragma solidity ^0.5.0;

import "./IERC1400Partition.sol";
import "../ERC1400Raw/ERC1400Raw.sol";


/**
 * @title ERC1400Partition
 * @dev ERC1400Partition logic
 */
contract ERC1400Partition is IERC1400Partition, ERC1400Raw {

  /******************** Mappings to find partition ******************************/
  // List of partitions.
  bytes32[] internal _totalPartitions;

  // Mapping from partition to their index.
  mapping (bytes32 => uint256) internal _indexOfTotalPartitions;

  // Mapping from partition to global balance of corresponding partition.
  mapping (bytes32 => uint256) internal _totalSupplyByPartition;

  // Mapping from tokenHolder to their partitions.
  mapping (address => bytes32[]) internal _partitionsOf;

  // Mapping from (tokenHolder, partition) to their index.
  mapping (address => mapping (bytes32 => uint256)) internal _indexOfPartitionsOf;

  // Mapping from (tokenHolder, partition) to balance of corresponding partition.
  mapping (address => mapping (bytes32 => uint256)) internal _balanceOfByPartition;

  // List of token default partitions (for ERC20 compatibility).
  bytes32[] internal _defaultPartitions;
  /****************************************************************************/

  /**************** Mappings to find partition operators ************************/
  // Mapping from (tokenHolder, partition, operator) to 'approved for partition' status. [TOKEN-HOLDER-SPECIFIC]
  mapping (address => mapping (bytes32 => mapping (address => bool))) internal _authorizedOperatorByPartition;

  // Mapping from partition to controllers for the partition. [NOT TOKEN-HOLDER-SPECIFIC]
  mapping (bytes32 => address[]) internal _controllersByPartition;

  // Mapping from (partition, operator) to PartitionController status. [NOT TOKEN-HOLDER-SPECIFIC]
  mapping (bytes32 => mapping (address => bool)) internal _isControllerByPartition;
  /****************************************************************************/

  /**
   * [ERC1400Partition CONSTRUCTOR]
   * @dev Initialize ERC1400Partition parameters + register
   * the contract implementation in ERC1820Registry.
   * @param name Name of the token.
   * @param symbol Symbol of the token.
   * @param granularity Granularity of the token.
   * @param controllers Array of initial controllers.
   * @param certificateSigner Address of the off-chain service which signs the
   * conditional ownership certificates required for token transfers, issuance,
   * redemption (Cf. CertificateController.sol).
   */
  constructor(
    string memory name,
    string memory symbol,
    uint256 granularity,
    address[] memory controllers,
    address certificateSigner,
    bytes32[] memory defaultPartitions
  )
    public
    ERC1400Raw(name, symbol, granularity, controllers, certificateSigner)
  {
    _defaultPartitions = defaultPartitions;
  }

  /********************** ERC1400Partition EXTERNAL FUNCTIONS **************************/

  /**
   * [ERC1400Partition INTERFACE (1/10)]
   * @dev Get balance of a tokenholder for a specific partition.
   * @param partition Name of the partition.
   * @param tokenHolder Address for which the balance is returned.
   * @return Amount of token of partition 'partition' held by 'tokenHolder' in the token contract.
   */
  function balanceOfByPartition(bytes32 partition, address tokenHolder) external view returns (uint256) {
    return _balanceOfByPartition[tokenHolder][partition];
  }

  /**
   * [ERC1400Partition INTERFACE (2/10)]
   * @dev Get partitions index of a tokenholder.
   * @param tokenHolder Address for which the partitions index are returned.
   * @return Array of partitions index of 'tokenHolder'.
   */
  function partitionsOf(address tokenHolder) external view returns (bytes32[] memory) {
    return _partitionsOf[tokenHolder];
  }

  /**
   * [ERC1400Partition INTERFACE (3/10)]
   * @dev Transfer tokens from a specific partition.
   * @param partition Name of the partition.
   * @param to Token recipient.
   * @param value Number of tokens to transfer.
   * @param data Information attached to the transfer, by the token holder. [CONTAINS THE CONDITIONAL OWNERSHIP CERTIFICATE]
   * @return Destination partition.
   */
  function transferByPartition(
    bytes32 partition,
    address to,
    uint256 value,
    bytes calldata data
  )
    external
    isValidCertificate(data)
    returns (bytes32)
  {
    return _transferByPartition(partition, msg.sender, msg.sender, to, value, data, "", true);
  }

  /**
   * [ERC1400Partition INTERFACE (4/10)]
   * @dev Transfer tokens from a specific partition through an operator.
   * @param partition Name of the partition.
   * @param from Token holder.
   * @param to Token recipient.
   * @param value Number of tokens to transfer.
   * @param data Information attached to the transfer. [CAN CONTAIN THE DESTINATION PARTITION]
   * @param operatorData Information attached to the transfer, by the operator. [CONTAINS THE CONDITIONAL OWNERSHIP CERTIFICATE]
   * @return Destination partition.
   */
  function operatorTransferByPartition(
    bytes32 partition,
    address from,
    address to,
    uint256 value,
    bytes calldata data,
    bytes calldata operatorData
  )
    external
    isValidCertificate(operatorData)
    returns (bytes32)
  {
    require(_isOperatorForPartition(partition, msg.sender, from), "A7"); // Transfer Blocked - Identity restriction

    return _transferByPartition(partition, msg.sender, from, to, value, data, operatorData, true);
  }

  /**
   * [ERC1400Partition INTERFACE (5/10)]
   * @dev Get default partitions to transfer from.
   * Function used for ERC1400Raw and ERC20 backwards compatibility.
   * For example, a security token may return the bytes32("unrestricted").
   * @return Array of default partitions.
   */
  function getDefaultPartitions() external view returns (bytes32[] memory) {
    return _defaultPartitions;
  }

  /**
   * [ERC1400Partition INTERFACE (6/10)]
   * @dev Set default partitions to transfer from.
   * Function used for ERC1400Raw and ERC20 backwards compatibility.
   * @param partitions partitions to use by default when not specified.
   */
  function setDefaultPartitions(bytes32[] calldata partitions) external onlyOwner {
    _defaultPartitions = partitions;
  }

  /**
   * [ERC1400Partition INTERFACE (7/10)]
   * @dev Get controllers for a given partition.
   * Function used for ERC1400Raw and ERC20 backwards compatibility.
   * @param partition Name of the partition.
   * @return Array of controllers for partition.
   */
  function controllersByPartition(bytes32 partition) external view returns (address[] memory) {
    return _controllersByPartition[partition];
  }

  /**
   * [ERC1400Partition INTERFACE (8/10)]
   * @dev Set 'operator' as an operator for 'msg.sender' for a given partition.
   * @param partition Name of the partition.
   * @param operator Address to set as an operator for 'msg.sender'.
   */
  function authorizeOperatorByPartition(bytes32 partition, address operator) external {
    _authorizedOperatorByPartition[msg.sender][partition][operator] = true;
    emit AuthorizedOperatorByPartition(partition, operator, msg.sender);
  }

  /**
   * [ERC1400Partition INTERFACE (9/10)]
   * @dev Remove the right of the operator address to be an operator on a given
   * partition for 'msg.sender' and to transfer and redeem tokens on its behalf.
   * @param partition Name of the partition.
   * @param operator Address to rescind as an operator on given partition for 'msg.sender'.
   */
  function revokeOperatorByPartition(bytes32 partition, address operator) external {
    _authorizedOperatorByPartition[msg.sender][partition][operator] = false;
    emit RevokedOperatorByPartition(partition, operator, msg.sender);
  }

  /**
   * [ERC1400Partition INTERFACE (10/10)]
   * @dev Indicate whether the operator address is an operator of the tokenHolder
   * address for the given partition.
   * @param partition Name of the partition.
   * @param operator Address which may be an operator of tokenHolder for the given partition.
   * @param tokenHolder Address of a token holder which may have the operator address as an operator for the given partition.
   * @return 'true' if 'operator' is an operator of 'tokenHolder' for partition 'partition' and 'false' otherwise.
   */
  function isOperatorForPartition(bytes32 partition, address operator, address tokenHolder) external view returns (bool) {
    return _isOperatorForPartition(partition, operator, tokenHolder);
  }

  /********************** ERC1400Partition INTERNAL FUNCTIONS **************************/

  /**
   * [INTERNAL]
   * @dev Indicate whether the operator address is an operator of the tokenHolder
   * address for the given partition.
   * @param partition Name of the partition.
   * @param operator Address which may be an operator of tokenHolder for the given partition.
   * @param tokenHolder Address of a token holder which may have the operator address as an operator for the given partition.
   * @return 'true' if 'operator' is an operator of 'tokenHolder' for partition 'partition' and 'false' otherwise.
   */
   function _isOperatorForPartition(bytes32 partition, address operator, address tokenHolder) internal view returns (bool) {
     return (_isOperator(operator, tokenHolder)
       || _authorizedOperatorByPartition[tokenHolder][partition][operator]
       || (_isControllable && _isControllerByPartition[partition][operator])
     );
   }

  /**
   * [INTERNAL]
   * @dev Transfer tokens from a specific partition.
   * @param fromPartition Partition of the tokens to transfer.
   * @param operator The address performing the transfer.
   * @param from Token holder.
   * @param to Token recipient.
   * @param value Number of tokens to transfer.
   * @param data Information attached to the transfer. [CAN CONTAIN THE DESTINATION PARTITION]
   * @param operatorData Information attached to the transfer, by the operator (if any).
   * @param preventLocking 'true' if you want this function to throw when tokens are sent to a contract not
   * implementing 'erc777tokenHolder'.
   * @return Destination partition.
   */
  function _transferByPartition(
    bytes32 fromPartition,
    address operator,
    address from,
    address to,
    uint256 value,
    bytes memory data,
    bytes memory operatorData,
    bool preventLocking
  )
    internal
    returns (bytes32)
  {
    require(_balanceOfByPartition[from][fromPartition] >= value, "A4"); // Transfer Blocked - Sender balance insufficient

    bytes32 toPartition = fromPartition;

    if(operatorData.length != 0 && data.length >= 64) {
      toPartition = _getDestinationPartition(fromPartition, data);
    }

    _removeTokenFromPartition(from, fromPartition, value);
    _transferWithData(fromPartition, operator, from, to, value, data, operatorData, preventLocking);
    _addTokenToPartition(to, toPartition, value);

    emit TransferByPartition(fromPartition, operator, from, to, value, data, operatorData);

    if(toPartition != fromPartition) {
      emit ChangedPartition(fromPartition, toPartition, value);
    }

    return toPartition;
  }

  /**
   * [INTERNAL]
   * @dev Remove a token from a specific partition.
   * @param from Token holder.
   * @param partition Name of the partition.
   * @param value Number of tokens to transfer.
   */
  function _removeTokenFromPartition(address from, bytes32 partition, uint256 value) internal {
    _balanceOfByPartition[from][partition] = _balanceOfByPartition[from][partition].sub(value);
    _totalSupplyByPartition[partition] = _totalSupplyByPartition[partition].sub(value);

    // If the total supply is zero, finds and deletes the partition.
    if(_totalSupplyByPartition[partition] == 0) {
      uint256 index1 = _indexOfTotalPartitions[partition];
      require(index1 > 0, "A8"); // Transfer Blocked - Token restriction

      // move the last item into the index being vacated
      bytes32 lastValue = _totalPartitions[_totalPartitions.length - 1];
      _totalPartitions[index1 - 1] = lastValue; // adjust for 1-based indexing
      _indexOfTotalPartitions[lastValue] = index1;

      _totalPartitions.length -= 1;
      _indexOfTotalPartitions[partition] = 0;
    }

    // If the balance of the TokenHolder's partition is zero, finds and deletes the partition.
    if(_balanceOfByPartition[from][partition] == 0) {
      uint256 index2 = _indexOfPartitionsOf[from][partition];
      require(index2 > 0, "A8"); // Transfer Blocked - Token restriction

      // move the last item into the index being vacated
      bytes32 lastValue = _partitionsOf[from][_partitionsOf[from].length - 1];
      _partitionsOf[from][index2 - 1] = lastValue;  // adjust for 1-based indexing
      _indexOfPartitionsOf[from][lastValue] = index2;

      _partitionsOf[from].length -= 1;
      _indexOfPartitionsOf[from][partition] = 0;
    }

  }

  /**
   * [INTERNAL]
   * @dev Add a token to a specific partition.
   * @param to Token recipient.
   * @param partition Name of the partition.
   * @param value Number of tokens to transfer.
   */
  function _addTokenToPartition(address to, bytes32 partition, uint256 value) internal {
    if(value != 0) {
      if (_indexOfPartitionsOf[to][partition] == 0) {
        _partitionsOf[to].push(partition);
        _indexOfPartitionsOf[to][partition] = _partitionsOf[to].length;
      }
      _balanceOfByPartition[to][partition] = _balanceOfByPartition[to][partition].add(value);

      if (_indexOfTotalPartitions[partition] == 0) {
        _totalPartitions.push(partition);
        _indexOfTotalPartitions[partition] = _totalPartitions.length;
      }
      _totalSupplyByPartition[partition] = _totalSupplyByPartition[partition].add(value);
    }
  }

  /**
   * [INTERNAL]
   * @dev Retrieve the destination partition from the 'data' field.
   * By convention, a partition change is requested ONLY when 'data' starts
   * with the flag: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
   * When the flag is detected, the destination tranche is extracted from the
   * 32 bytes following the flag.
   * @param fromPartition Partition of the tokens to transfer.
   * @param data Information attached to the transfer. [CAN CONTAIN THE DESTINATION PARTITION]
   * @return Destination partition.
   */
  function _getDestinationPartition(bytes32 fromPartition, bytes memory data) internal pure returns(bytes32 toPartition) {
    bytes32 changePartitionFlag = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
    bytes32 flag;
    assembly {
      flag := mload(add(data, 32))
    }
    if(flag == changePartitionFlag) {
      assembly {
        toPartition := mload(add(data, 64))
      }
    } else {
      toPartition = fromPartition;
    }
  }

  /********************* ERC1400Partition OPTIONAL FUNCTIONS ***************************/

  /**
   * [NOT MANDATORY FOR ERC1400Partition STANDARD]
   * @dev Get list of existing partitions.
   * @return Array of all exisiting partitions.
   */
  function totalPartitions() external view returns (bytes32[] memory) {
    return _totalPartitions;
  }

  /**
   * [NOT MANDATORY FOR ERC1400Partition STANDARD][SHALL BE CALLED ONLY FROM ERC1400]
   * @dev Set list of token partition controllers.
   * @param partition Name of the partition.
   * @param operators Controller addresses.
   */
   function _setPartitionControllers(bytes32 partition, address[] memory operators) internal {
     for (uint i = 0; i<_controllersByPartition[partition].length; i++){
       _isControllerByPartition[partition][_controllersByPartition[partition][i]] = false;
     }
     for (uint j = 0; j<operators.length; j++){
       _isControllerByPartition[partition][operators[j]] = true;
     }
     _controllersByPartition[partition] = operators;
   }

  /************** ERC1400Raw BACKWARDS RETROCOMPATIBILITY *************************/

  /**
   * [NOT MANDATORY FOR ERC1400Partition STANDARD][OVERRIDES ERC1400Raw METHOD]
   * @dev Transfer the value of tokens from the address 'msg.sender' to the address 'to'.
   * @param to Token recipient.
   * @param value Number of tokens to transfer.
   * @param data Information attached to the transfer, by the token holder. [CONTAINS THE CONDITIONAL OWNERSHIP CERTIFICATE]
   */
  function transferWithData(address to, uint256 value, bytes calldata data)
    external
    isValidCertificate(data)
  {
    _transferByDefaultPartitions(msg.sender, msg.sender, to, value, data, "", true);
  }

  /**
   * [NOT MANDATORY FOR ERC1400Partition STANDARD][OVERRIDES ERC1400Raw METHOD]
   * @dev Transfer the value of tokens on behalf of the address from to the address to.
   * @param from Token holder (or 'address(0)'' to set from to 'msg.sender').
   * @param to Token recipient.
   * @param value Number of tokens to transfer.
   * @param data Information attached to the transfer, and intended for the token holder ('from'). [CAN CONTAIN THE DESTINATION PARTITION]
   * @param operatorData Information attached to the transfer by the operator. [CONTAINS THE CONDITIONAL OWNERSHIP CERTIFICATE]
   */
  function transferFromWithData(address from, address to, uint256 value, bytes calldata data, bytes calldata operatorData)
    external
    isValidCertificate(operatorData)
  {
    require(_isOperator(msg.sender, from), "A7"); // Transfer Blocked - Identity restriction

    _transferByDefaultPartitions(msg.sender, from, to, value, data, operatorData, true);
  }

  /**
   * [NOT MANDATORY FOR ERC1400Partition STANDARD][OVERRIDES ERC1400Raw METHOD]
   * @dev Empty function to erase ERC1400Raw redeem() function since it doesn't handle partitions.
   */
  function redeem(uint256 /*value*/, bytes calldata /*data*/) external { // Comments to avoid compilation warnings for unused variables.
    revert("A8: Transfer Blocked - Token restriction");
  }

  /**
   * [NOT MANDATORY FOR ERC1400Partition STANDARD][OVERRIDES ERC1400Raw METHOD]
   * @dev Empty function to erase ERC1400Raw redeemFrom() function since it doesn't handle partitions.
   */
  function redeemFrom(address /*from*/, uint256 /*value*/, bytes calldata /*data*/, bytes calldata /*operatorData*/) external { // Comments to avoid compilation warnings for unused variables.
    revert("A8: Transfer Blocked - Token restriction");
  }

  /**
   * [NOT MANDATORY FOR ERC1400Partition STANDARD]
   * @dev Transfer tokens from default partitions.
   * @param operator The address performing the transfer.
   * @param from Token holder.
   * @param to Token recipient.
   * @param value Number of tokens to transfer.
   * @param data Information attached to the transfer, and intended for the token holder ('from') [CAN CONTAIN THE DESTINATION PARTITION].
   * @param operatorData Information attached to the transfer by the operator (if any).
   * @param preventLocking 'true' if you want this function to throw when tokens are sent to a contract not
   * implementing 'erc777tokenHolder'.
   */
  function _transferByDefaultPartitions(
    address operator,
    address from,
    address to,
    uint256 value,
    bytes memory data,
    bytes memory operatorData,
    bool preventLocking
  )
    internal
  {
    require(_defaultPartitions.length != 0, "A8"); // Transfer Blocked - Token restriction

    uint256 _remainingValue = value;
    uint256 _localBalance;

    for (uint i = 0; i < _defaultPartitions.length; i++) {
      _localBalance = _balanceOfByPartition[from][_defaultPartitions[i]];
      if(_remainingValue <= _localBalance) {
        _transferByPartition(_defaultPartitions[i], operator, from, to, _remainingValue, data, operatorData, preventLocking);
        _remainingValue = 0;
        break;
      } else if (_localBalance != 0) {
        _transferByPartition(_defaultPartitions[i], operator, from, to, _localBalance, data, operatorData, preventLocking);
        _remainingValue = _remainingValue - _localBalance;
      }
    }

    require(_remainingValue == 0, "A8"); // Transfer Blocked - Token restriction
  }
}

/*
 * This code has not been reviewed.
 * Do not use or deploy this code before reviewing it personally first.
 */
pragma solidity ^0.5.0;

/**
 * @title IERC1400Partition partially fungible token standard
 * @dev ERC1400Partition interface
 */
interface IERC1400Partition {

    // Token Information
    function balanceOfByPartition(bytes32 partition, address tokenHolder) external view returns (uint256); // 1/10
    function partitionsOf(address tokenHolder) external view returns (bytes32[] memory); // 2/10

    // Token Transfers
    function transferByPartition(bytes32 partition, address to, uint256 value, bytes calldata data) external returns (bytes32); // 3/10
    function operatorTransferByPartition(bytes32 partition, address from, address to, uint256 value, bytes calldata data, bytes calldata operatorData) external returns (bytes32); // 4/10

    // Default Partition Management
    function getDefaultPartitions() external view returns (bytes32[] memory); // 5/10
    function setDefaultPartitions(bytes32[] calldata partitions) external; // 6/10

    // Operators
    function controllersByPartition(bytes32 partition) external view returns (address[] memory); // 7/10
    function authorizeOperatorByPartition(bytes32 partition, address operator) external; // 8/10
    function revokeOperatorByPartition(bytes32 partition, address operator) external; // 9/10
    function isOperatorForPartition(bytes32 partition, address operator, address tokenHolder) external view returns (bool); // 10/10

    // Transfer Events
    event TransferByPartition(
        bytes32 indexed fromPartition,
        address operator,
        address indexed from,
        address indexed to,
        uint256 value,
        bytes data,
        bytes operatorData
    );

    event ChangedPartition(
        bytes32 indexed fromPartition,
        bytes32 indexed toPartition,
        uint256 value
    );

    // Operator Events
    event AuthorizedOperatorByPartition(bytes32 indexed partition, address indexed operator, address indexed tokenHolder);
    event RevokedOperatorByPartition(bytes32 indexed partition, address indexed operator, address indexed tokenHolder);

}

/*
 * This code has not been reviewed.
 * Do not use or deploy this code before reviewing it personally first.
 */
pragma solidity ^0.5.0;

import "openzeppelin-solidity/contracts/math/SafeMath.sol";
import "openzeppelin-solidity/contracts/ownership/Ownable.sol";
import "openzeppelin-solidity/contracts/utils/ReentrancyGuard.sol";
import "erc1820/contracts/ERC1820Client.sol";

import "../../CertificateController/CertificateController.sol";

import "./IERC1400Raw.sol";
import "./IERC1400TokensSender.sol";
import "./IERC1400TokensRecipient.sol";


/**
 * @title ERC1400Raw
 * @dev ERC1400Raw logic
 */
contract ERC1400Raw is IERC1400Raw, Ownable, ERC1820Client, CertificateController, ReentrancyGuard {
  using SafeMath for uint256;

  string internal _name;
  string internal _symbol;
  uint256 internal _granularity;
  uint256 internal _totalSupply;

  // Indicate whether the token can still be controlled by operators or not anymore.
  bool internal _isControllable;

  // Mapping from tokenHolder to balance.
  mapping(address => uint256) internal _balances;

  /******************** Mappings related to operator **************************/
  // Mapping from (operator, tokenHolder) to authorized status. [TOKEN-HOLDER-SPECIFIC]
  mapping(address => mapping(address => bool)) internal _authorizedOperator;

  // Array of controllers. [GLOBAL - NOT TOKEN-HOLDER-SPECIFIC]
  address[] internal _controllers;

  // Mapping from operator to controller status. [GLOBAL - NOT TOKEN-HOLDER-SPECIFIC]
  mapping(address => bool) internal _isController;
  /****************************************************************************/

  /**
   * [ERC1400Raw CONSTRUCTOR]
   * @dev Initialize ERC1400Raw and CertificateController parameters + register
   * the contract implementation in ERC1820Registry.
   * @param name Name of the token.
   * @param symbol Symbol of the token.
   * @param granularity Granularity of the token.
   * @param controllers Array of initial controllers.
   * @param certificateSigner Address of the off-chain service which signs the
   * conditional ownership certificates required for token transfers, issuance,
   * redemption (Cf. CertificateController.sol).
   */
  constructor(
    string memory name,
    string memory symbol,
    uint256 granularity,
    address[] memory controllers,
    address certificateSigner
  )
    public
    CertificateController(certificateSigner)
  {
    _name = name;
    _symbol = symbol;
    _totalSupply = 0;
    require(granularity >= 1); // Constructor Blocked - Token granularity can not be lower than 1
    _granularity = granularity;

    _setControllers(controllers);
  }

  /********************** ERC1400Raw EXTERNAL FUNCTIONS ***************************/

  /**
   * [ERC1400Raw INTERFACE (1/13)]
   * @dev Get the name of the token, e.g., "MyToken".
   * @return Name of the token.
   */
  function name() external view returns(string memory) {
    return _name;
  }

  /**
   * [ERC1400Raw INTERFACE (2/13)]
   * @dev Get the symbol of the token, e.g., "MYT".
   * @return Symbol of the token.
   */
  function symbol() external view returns(string memory) {
    return _symbol;
  }

  /**
   * [ERC1400Raw INTERFACE (3/13)]
   * @dev Get the total number of issued tokens.
   * @return Total supply of tokens currently in circulation.
   */
  function totalSupply() external view returns (uint256) {
    return _totalSupply;
  }

  /**
   * [ERC1400Raw INTERFACE (4/13)]
   * @dev Get the balance of the account with address 'tokenHolder'.
   * @param tokenHolder Address for which the balance is returned.
   * @return Amount of token held by 'tokenHolder' in the token contract.
   */
  function balanceOf(address tokenHolder) external view returns (uint256) {
    return _balances[tokenHolder];
  }

  /**
   * [ERC1400Raw INTERFACE (5/13)]
   * @dev Get the smallest part of the token that’s not divisible.
   * @return The smallest non-divisible part of the token.
   */
  function granularity() external view returns(uint256) {
    return _granularity;
  }

  /**
   * [ERC1400Raw INTERFACE (6/13)]
   * @dev Get the list of controllers as defined by the token contract.
   * @return List of addresses of all the controllers.
   */
  function controllers() external view returns (address[] memory) {
    return _controllers;
  }

  /**
   * [ERC1400Raw INTERFACE (7/13)]
   * @dev Set a third party operator address as an operator of 'msg.sender' to transfer
   * and redeem tokens on its behalf.
   * @param operator Address to set as an operator for 'msg.sender'.
   */
  function authorizeOperator(address operator) external {
    require(operator != msg.sender);
    _authorizedOperator[operator][msg.sender] = true;
    emit AuthorizedOperator(operator, msg.sender);
  }

  /**
   * [ERC1400Raw INTERFACE (8/13)]
   * @dev Remove the right of the operator address to be an operator for 'msg.sender'
   * and to transfer and redeem tokens on its behalf.
   * @param operator Address to rescind as an operator for 'msg.sender'.
   */
  function revokeOperator(address operator) external {
    require(operator != msg.sender);
    _authorizedOperator[operator][msg.sender] = false;
    emit RevokedOperator(operator, msg.sender);
  }

  /**
   * [ERC1400Raw INTERFACE (9/13)]
   * @dev Indicate whether the operator address is an operator of the tokenHolder address.
   * @param operator Address which may be an operator of tokenHolder.
   * @param tokenHolder Address of a token holder which may have the operator address as an operator.
   * @return 'true' if operator is an operator of 'tokenHolder' and 'false' otherwise.
   */
  function isOperator(address operator, address tokenHolder) external view returns (bool) {
    return _isOperator(operator, tokenHolder);
  }

  /**
   * [ERC1400Raw INTERFACE (10/13)]
   * @dev Transfer the amount of tokens from the address 'msg.sender' to the address 'to'.
   * @param to Token recipient.
   * @param value Number of tokens to transfer.
   * @param data Information attached to the transfer, by the token holder. [CONTAINS THE CONDITIONAL OWNERSHIP CERTIFICATE]
   */
  function transferWithData(address to, uint256 value, bytes calldata data)
    external
    isValidCertificate(data)
  {
    _transferWithData("", msg.sender, msg.sender, to, value, data, "", true);
  }

  /**
   * [ERC1400Raw INTERFACE (11/13)]
   * @dev Transfer the amount of tokens on behalf of the address 'from' to the address 'to'.
   * @param from Token holder (or 'address(0)' to set from to 'msg.sender').
   * @param to Token recipient.
   * @param value Number of tokens to transfer.
   * @param data Information attached to the transfer, and intended for the token holder ('from').
   * @param operatorData Information attached to the transfer by the operator. [CONTAINS THE CONDITIONAL OWNERSHIP CERTIFICATE]
   */
  function transferFromWithData(address from, address to, uint256 value, bytes calldata data, bytes calldata operatorData)
    external
    isValidCertificate(operatorData)
  {
    require(_isOperator(msg.sender, from), "A7"); // Transfer Blocked - Identity restriction

    _transferWithData("", msg.sender, from, to, value, data, operatorData, true);
  }

  /**
   * [ERC1400Raw INTERFACE (12/13)]
   * @dev Redeem the amount of tokens from the address 'msg.sender'.
   * @param value Number of tokens to redeem.
   * @param data Information attached to the redemption, by the token holder. [CONTAINS THE CONDITIONAL OWNERSHIP CERTIFICATE]
   */
  function redeem(uint256 value, bytes calldata data)
    external
    isValidCertificate(data)
  {
    _redeem("", msg.sender, msg.sender, value, data, "");
  }

  /**
   * [ERC1400Raw INTERFACE (13/13)]
   * @dev Redeem the amount of tokens on behalf of the address from.
   * @param from Token holder whose tokens will be redeemed (or address(0) to set from to msg.sender).
   * @param value Number of tokens to redeem.
   * @param data Information attached to the redemption.
   * @param operatorData Information attached to the redemption, by the operator. [CONTAINS THE CONDITIONAL OWNERSHIP CERTIFICATE]
   */
  function redeemFrom(address from, uint256 value, bytes calldata data, bytes calldata operatorData)
    external
    isValidCertificate(operatorData)
  {
    require(_isOperator(msg.sender, from), "A7"); // Transfer Blocked - Identity restriction

    _redeem("", msg.sender, from, value, data, operatorData);
  }

  /********************** ERC1400Raw INTERNAL FUNCTIONS ***************************/

  /**
   * [INTERNAL]
   * @dev Check if 'value' is multiple of the granularity.
   * @param value The quantity that want's to be checked.
   * @return 'true' if 'value' is a multiple of the granularity.
   */
  function _isMultiple(uint256 value) internal view returns(bool) {
    return(value.div(_granularity).mul(_granularity) == value);
  }

  /**
   * [INTERNAL]
   * @dev Check whether an address is a regular address or not.
   * @param addr Address of the contract that has to be checked.
   * @return 'true' if 'addr' is a regular address (not a contract).
   */
  function _isRegularAddress(address addr) internal view returns(bool) {
    if (addr == address(0)) { return false; }
    uint size;
    assembly { size := extcodesize(addr) } // solhint-disable-line no-inline-assembly
    return size == 0;
  }

  /**
   * [INTERNAL]
   * @dev Indicate whether the operator address is an operator of the tokenHolder address.
   * @param operator Address which may be an operator of 'tokenHolder'.
   * @param tokenHolder Address of a token holder which may have the 'operator' address as an operator.
   * @return 'true' if 'operator' is an operator of 'tokenHolder' and 'false' otherwise.
   */
  function _isOperator(address operator, address tokenHolder) internal view returns (bool) {
    return (operator == tokenHolder
      || _authorizedOperator[operator][tokenHolder]
      || (_isControllable && _isController[operator])
    );
  }

   /**
    * [INTERNAL]
    * @dev Perform the transfer of tokens.
    * @param partition Name of the partition (bytes32 to be left empty for ERC1400Raw transfer).
    * @param operator The address performing the transfer.
    * @param from Token holder.
    * @param to Token recipient.
    * @param value Number of tokens to transfer.
    * @param data Information attached to the transfer.
    * @param operatorData Information attached to the transfer by the operator (if any)..
    * @param preventLocking 'true' if you want this function to throw when tokens are sent to a contract not
    * implementing 'erc777tokenHolder'.
    * ERC1400Raw native transfer functions MUST set this parameter to 'true', and backwards compatible ERC20 transfer
    * functions SHOULD set this parameter to 'false'.
    */
  function _transferWithData(
    bytes32 partition,
    address operator,
    address from,
    address to,
    uint256 value,
    bytes memory data,
    bytes memory operatorData,
    bool preventLocking
  )
    internal
    nonReentrant
  {
    require(_isMultiple(value), "A9"); // Transfer Blocked - Token granularity
    require(to != address(0), "A6"); // Transfer Blocked - Receiver not eligible
    require(_balances[from] >= value, "A4"); // Transfer Blocked - Sender balance insufficient

    _callSender(partition, operator, from, to, value, data, operatorData);

    _balances[from] = _balances[from].sub(value);
    _balances[to] = _balances[to].add(value);

    _callRecipient(partition, operator, from, to, value, data, operatorData, preventLocking);

    emit TransferWithData(operator, from, to, value, data, operatorData);
  }

  /**
   * [INTERNAL]
   * @dev Perform the token redemption.
   * @param partition Name of the partition (bytes32 to be left empty for ERC1400Raw transfer).
   * @param operator The address performing the redemption.
   * @param from Token holder whose tokens will be redeemed.
   * @param value Number of tokens to redeem.
   * @param data Information attached to the redemption.
   * @param operatorData Information attached to the redemption, by the operator (if any).
   */
  function _redeem(bytes32 partition, address operator, address from, uint256 value, bytes memory data, bytes memory operatorData)
    internal
    nonReentrant
  {
    require(_isMultiple(value), "A9"); // Transfer Blocked - Token granularity
    require(from != address(0), "A5"); // Transfer Blocked - Sender not eligible
    require(_balances[from] >= value, "A4"); // Transfer Blocked - Sender balance insufficient

    _callSender(partition, operator, from, address(0), value, data, operatorData);

    _balances[from] = _balances[from].sub(value);
    _totalSupply = _totalSupply.sub(value);

    emit Redeemed(operator, from, value, data, operatorData);
  }

  /**
   * [INTERNAL]
   * @dev Check for 'ERC1400TokensSender' hook on the sender and call it.
   * May throw according to 'preventLocking'.
   * @param partition Name of the partition (bytes32 to be left empty for ERC1400Raw transfer).
   * @param operator Address which triggered the balance decrease (through transfer or redemption).
   * @param from Token holder.
   * @param to Token recipient for a transfer and 0x for a redemption.
   * @param value Number of tokens the token holder balance is decreased by.
   * @param data Extra information.
   * @param operatorData Extra information, attached by the operator (if any).
   */
  function _callSender(
    bytes32 partition,
    address operator,
    address from,
    address to,
    uint256 value,
    bytes memory data,
    bytes memory operatorData
  )
    internal
  {
    address senderImplementation;
    senderImplementation = interfaceAddr(from, "ERC1400TokensSender");

    if (senderImplementation != address(0)) {
      IERC1400TokensSender(senderImplementation).tokensToTransfer(partition, operator, from, to, value, data, operatorData);
    }
  }

  /**
   * [INTERNAL]
   * @dev Check for 'ERC1400TokensRecipient' hook on the recipient and call it.
   * May throw according to 'preventLocking'.
   * @param partition Name of the partition (bytes32 to be left empty for ERC1400Raw transfer).
   * @param operator Address which triggered the balance increase (through transfer or issuance).
   * @param from Token holder for a transfer and 0x for an issuance.
   * @param to Token recipient.
   * @param value Number of tokens the recipient balance is increased by.
   * @param data Extra information, intended for the token holder ('from').
   * @param operatorData Extra information attached by the operator (if any).
   * @param preventLocking 'true' if you want this function to throw when tokens are sent to a contract not
   * implementing 'ERC1400TokensRecipient'.
   * ERC1400Raw native transfer functions MUST set this parameter to 'true', and backwards compatible ERC20 transfer
   * functions SHOULD set this parameter to 'false'.
   */
  function _callRecipient(
    bytes32 partition,
    address operator,
    address from,
    address to,
    uint256 value,
    bytes memory data,
    bytes memory operatorData,
    bool preventLocking
  )
    internal
  {
    address recipientImplementation;
    recipientImplementation = interfaceAddr(to, "ERC1400TokensRecipient");

    if (recipientImplementation != address(0)) {
      IERC1400TokensRecipient(recipientImplementation).tokensReceived(partition, operator, from, to, value, data, operatorData);
    } else if (preventLocking) {
      require(_isRegularAddress(to), "A6"); // Transfer Blocked - Receiver not eligible
    }
  }

  /**
   * [INTERNAL]
   * @dev Perform the issuance of tokens.
   * @param partition Name of the partition (bytes32 to be left empty for ERC1400Raw transfer).
   * @param operator Address which triggered the issuance.
   * @param to Token recipient.
   * @param value Number of tokens issued.
   * @param data Information attached to the issuance, and intended for the recipient (to).
   * @param operatorData Information attached to the issuance by the operator (if any).
   */
  function _issue(bytes32 partition, address operator, address to, uint256 value, bytes memory data, bytes memory operatorData) internal nonReentrant {
    require(_isMultiple(value), "A9"); // Transfer Blocked - Token granularity
    require(to != address(0), "A6"); // Transfer Blocked - Receiver not eligible

    _totalSupply = _totalSupply.add(value);
    _balances[to] = _balances[to].add(value);

    _callRecipient(partition, operator, address(0), to, value, data, operatorData, true);

    emit Issued(operator, to, value, data, operatorData);
  }

  /********************** ERC1400Raw OPTIONAL FUNCTIONS ***************************/

  /**
   * [NOT MANDATORY FOR ERC1400Raw STANDARD]
   * @dev Set list of token controllers.
   * @param operators Controller addresses.
   */
  function _setControllers(address[] memory operators) internal {
    for (uint i = 0; i<_controllers.length; i++){
      _isController[_controllers[i]] = false;
    }
    for (uint j = 0; j<operators.length; j++){
      _isController[operators[j]] = true;
    }
    _controllers = operators;
  }

}

pragma solidity ^0.5.0;

import "./ERC1400Raw.sol";



/**
 * @title ERC1400RawIssuable
 * @dev ERC1400Raw issuance logic
 */
contract ERC1400RawIssuable is ERC1400Raw, MinterRole {

  /**
   * [NOT MANDATORY FOR ERC1400Raw STANDARD]
   * @dev Issue the amout of tokens for the recipient 'to'.
   * @param to Token recipient.
   * @param value Number of tokens issued.
   * @param data Information attached to the issuance, by the token holder. [CONTAINS THE CONDITIONAL OWNERSHIP CERTIFICATE]
   * @return A boolean that indicates if the operation was successful.
   */
  function issue(address to, uint256 value, bytes calldata data)
    external
    isValidCertificate(data)
    onlyMinter
    returns (bool)
  {
    _issue("", msg.sender, to, value, data, "");

    return true;
  }

}

/*
 * This code has not been reviewed.
 * Do not use or deploy this code before reviewing it personally first.
 */
pragma solidity ^0.5.0;

/**
 * @title IERC1400Raw token standard
 * @dev ERC1400Raw interface
 */
interface IERC1400Raw {

  function name() external view returns (string memory); // 1/13
  function symbol() external view returns (string memory); // 2/13
  function totalSupply() external view returns (uint256); // 3/13
  function balanceOf(address owner) external view returns (uint256); // 4/13
  function granularity() external view returns (uint256); // 5/13

  function controllers() external view returns (address[] memory); // 6/13
  function authorizeOperator(address operator) external; // 7/13
  function revokeOperator(address operator) external; // 8/13
  function isOperator(address operator, address tokenHolder) external view returns (bool); // 9/13

  function transferWithData(address to, uint256 value, bytes calldata data) external; // 10/13
  function transferFromWithData(address from, address to, uint256 value, bytes calldata data, bytes calldata operatorData) external; // 11/13

  function redeem(uint256 value, bytes calldata data) external; // 12/13
  function redeemFrom(address from, uint256 value, bytes calldata data, bytes calldata operatorData) external; // 13/13

  event TransferWithData(
    address indexed operator,
    address indexed from,
    address indexed to,
    uint256 value,
    bytes data,
    bytes operatorData
  );
  event Issued(address indexed operator, address indexed to, uint256 value, bytes data, bytes operatorData);
  event Redeemed(address indexed operator, address indexed from, uint256 value, bytes data, bytes operatorData);
  event AuthorizedOperator(address indexed operator, address indexed tokenHolder);
  event RevokedOperator(address indexed operator, address indexed tokenHolder);

}

/*
 * This code has not been reviewed.
 * Do not use or deploy this code before reviewing it personally first.
 */
pragma solidity ^0.5.0;

/**
 * @title IERC1400TokensRecipient
 * @dev ERC1400TokensRecipient interface
 */
interface IERC1400TokensRecipient {

  function canReceive(
    bytes32 partition,
    address from,
    address to,
    uint value,
    bytes calldata data,
    bytes calldata operatorData
  ) external view returns(bool);

  function tokensReceived(
    bytes32 partition,
    address operator,
    address from,
    address to,
    uint value,
    bytes calldata data,
    bytes calldata operatorData
  ) external;

}
/*
 * This code has not been reviewed.
 * Do not use or deploy this code before reviewing it personally first.
 */
pragma solidity ^0.5.0;

/**
 * @title IERC1400TokensSender
 * @dev ERC1400TokensSender interface
 */
interface IERC1400TokensSender {

  function canTransfer(
    bytes32 partition,
    address from,
    address to,
    uint value,
    bytes calldata data,
    bytes calldata operatorData
  ) external view returns(bool);

  function tokensToTransfer(
    bytes32 partition,
    address operator,
    address from,
    address to,
    uint value,
    bytes calldata data,
    bytes calldata operatorData
  ) external;

}

/*
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with GSN meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
contract Context {
    // Empty internal constructor, to prevent people from mistakenly deploying
    // an instance of this contract, which should be used via inheritance.
    constructor () internal { }
    // solhint-disable-previous-line no-empty-blocks

    function _msgSender() internal view returns (address payable) {
        return msg.sender;
    }

    function _msgData() internal view returns (bytes memory) {
        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
        return msg.data;
    }
}

/**
 * @title Roles
 * @dev Library for managing addresses assigned to a Role.
 */
library Roles {
    struct Role {
        mapping (address => bool) bearer;
    }

    /**
     * @dev Give an account access to this role.
     */
    function add(Role storage role, address account) internal {
        require(!has(role, account), "Roles: account already has role");
        role.bearer[account] = true;
    }

    /**
     * @dev Remove an account's access to this role.
     */
    function remove(Role storage role, address account) internal {
        require(has(role, account), "Roles: account does not have role");
        role.bearer[account] = false;
    }

    /**
     * @dev Check if an account has this role.
     * @return bool
     */
    function has(Role storage role, address account) internal view returns (bool) {
        require(account != address(0), "Roles: account is the zero address");
        return role.bearer[account];
    }
}

contract MinterRole is Context {
    using Roles for Roles.Role;

    event MinterAdded(address indexed account);
    event MinterRemoved(address indexed account);

    Roles.Role private _minters;

    constructor () internal {
        _addMinter(_msgSender());
    }

    modifier onlyMinter() {
        require(isMinter(_msgSender()), "MinterRole: caller does not have the Minter role");
        _;
    }

    function isMinter(address account) public view returns (bool) {
        return _minters.has(account);
    }

    function addMinter(address account) public onlyMinter {
        _addMinter(account);
    }

    function renounceMinter() public {
        _removeMinter(_msgSender());
    }

    function _addMinter(address account) internal {
        _minters.add(account);
        emit MinterAdded(account);
    }

    function _removeMinter(address account) internal {
        _minters.remove(account);
        emit MinterRemoved(account);
    }
}